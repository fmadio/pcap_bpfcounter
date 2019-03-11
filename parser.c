//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2018, fmad engineering llc 
//
// input parser 
//
// run each BPF filter
//
//---------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/ioctl.h>
#include <linux/sched.h>

#include "libpcap/pcap.h"
#include "fTypes.h"
#include "fProfile.h"
#include "lua.h"

//-------------------------------------------------------------------------------------------------

#define RMON1_RUNT			0
#define RMON1_64			1
#define RMON1_64_127		2
#define RMON1_128_255		3
#define RMON1_256_511		4
#define RMON1_512_1023		5
#define RMON1_1024_1518		6
#define RMON1_1519_2047		7
#define RMON1_2048_4095		8
#define RMON1_4096_8191		9
#define RMON1_8192			10
#define RMON1_OVER			11
#define RMON1_MAX			12

//#define TIME_BIN_MAX		(60*60)
#define TIME_BIN_MAX		(600000)			// 60sec / 100usec

typedef struct
{
	u32				BinMax;						// max entries
	u32				BinCnt;						// max entries
	u16*			BinListIndex;				// list of time indexs to add 
	u16*			BinListWire;				// byte count for that index 

	u32*			BinPkt;						// actual histogram 
	u32*			BinByte;					// only valid in the pipeline stats struct 

	u64				Pkt;						// number of pkts/bytes added in this time slot
	u64				Byte;

	u32				RMON1[RMON1_MAX];			// time RMON stats

} PipelineTime_t;

typedef struct PipelineStats_t
{
	u64				SeqNo;							// packet block sequence no
	bool			IsFlush;						// flush pipeline after updating

	u64				LastTS;							// TS of last packet hit
	u64				AllPkt;							// total packets checked (inc BPF miss) 
	u64				AllByte;						// used to calcuate raio of this BPF flow

	u64				TotalPkt;						// total packets hit
	u64				TotalByte;						// total bytes hit 

	u64				TCPCnt_FIN;						// total tcp FIN pkts 
	u64				TCPCnt_SYN;						// total tcp SYN pkts 
	u64				TCPCnt_RST;						// total tcp RST pkts 
	u64				TCPCnt_ACK;						// total tcp ACK pkts 
	u64				TCPCnt_PSH;						// total tcp PSH pkts 

	PipelineTime_t	Time;

	// next in free list
	struct PipelineStats_t* FreeNext;				// next in free list

	// next in queued list 
	struct PipelineStats_t* QueueNext;				// next in per pipeline queue

} PipelineStats_t;

typedef struct
{
	// rule definition 
	u8					Name[256];					// string name of the expression

	// output files
	u8					OutputFileName[1024];		// full path of output name
	FILE*				OutputFile;					// file handle to write
	u64					OutputNS;					// nanos between outputs 

	bool				BPFValid;					// BPF expression compiled sucessfully
	u8					BPF[1024];
	u8					BPFCode[16*1024];

	u32					TimeBinMax;					// max bins
	u64					TimeBinNS;					// time bin in nanos	

	u64					StatsSeqNo;					// next stats seq no to update
	PipelineStats_t		Stats;						// current aggregated stats 
													// for the pipeline 

	u32					QueueLock;					// mutual exclusion access to the queue
	s32					QueueDepth;					// depth of the queue
	PipelineStats_t*	QueueHead[32];				// one queue head per cpu 
	PipelineStats_t*	QueueTail[32];				// one queue head per cpu 

} Pipeline_t;

typedef struct PacketBlock_t
{
	u64						SeqNo;					// packet block seq no

	u32						PktCnt;					// number of packets in this buffer
	u32						ByteWire;				// total wire bytes 
	u32						ByteCapture;			// total captured bytes 

	u64						TSFirst;				// first Pkt TS
	u64						TSLast;					// last Pkt TS

	u32						BufferMax;				// max size
	u8*						Buffer;					// memory buffer
	u32						BufferLength;			// length of valid data in buffer

	bool					IsOutput;				// chunk cross the output boundary
	u32						OutputSeqNo;			// ensure it writes in-order
	u64						OutputTS;				// TS when to flush 

	struct PacketBlock_t*	FreeNext;				// next in free list

} PacketBlock_t;

//-------------------------------------------------------------------------------------------------

extern u64				g_OutputTimeNS;					// time between outputs

static u32				s_PipelinePos 		= 0;
static u32				s_PipelineMax 		= 16*1024;
static Pipeline_t* 		s_PipelineList[16*1024];	

static PacketBlock_t*	s_PacketBlockFree 	= NULL;		// free packet buffer list

static u32				s_PacketBlockMax	= 64;		// number of blocks to allocate

static volatile u32		s_PacketBlockPut	= 0;		// packet blocks ready for processing	
static volatile u32		s_PacketBlockGet	= 0;		// packet blocks completed processing
static volatile u32		s_PacketBlockMsk	= 0x7f;		// 
static PacketBlock_t*	s_PacketBlockRing[128];			// packet block queue

static PipelineStats_t*	s_PipeStatsFree		= NULL;		// free stats list
static u32				s_PipeStatsListMax	= 2048;		// number of stats entries to allocate 
static u32				s_PipeStatsLock		= 0;		// mutual exclusion for alloc/free

u64						g_TotalMemory		= 0;		// total memory allocated

u32						g_CPUCore			= 31;		// main cpu mapping
u32						g_CPUWorker[32]		= {30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20};
u32						g_CPUActive			= 1;		// number of worker cpus active

volatile bool			g_Exit				= false;	// global exit request

static pthread_t   		s_PktBlockThread[16];			// worker decode thread list
static u32				s_PktBlockLock		= 0;		// mutual exculsion for alloc/free

//-------------------------------------------------------------------------------------------------

static inline u32 Length2RMON1(const u32 Length)
{
	if (Length <    64) return RMON1_RUNT;
	if (Length ==   64) return RMON1_64;
	if (Length <=  127) return RMON1_64_127;
	if (Length <=  255) return RMON1_128_255;
	if (Length <=  511) return RMON1_256_511;
	if (Length <= 1023) return RMON1_512_1023;
	if (Length <= 1518) return RMON1_1024_1518;
	if (Length <= 2047) return RMON1_1519_2047;
	if (Length <= 4095) return RMON1_2048_4095;
	if (Length <= 8191) return RMON1_4096_8191;

	return RMON1_8192;
}

//-------------------------------------------------------------------------------------------------
// create a new pipeline 
int lpipe_create(lua_State* L)
{
	Pipeline_t*		Pipe = (Pipeline_t*)malloc( sizeof(Pipeline_t) );
	memset(Pipe, 0, sizeof(Pipeline_t));
	g_TotalMemory += sizeof(Pipeline_t);

	u32 Index 				= s_PipelinePos++;	
	s_PipelineList[Index]	= Pipe;

	const u8* Name = lua_tostring(L, -1);	
	strncpy(Pipe->Name, Name, sizeof(Pipe->Name) );

	printf("[%-40s] create a pipeline\n", Pipe->Name);

	Pipe->OutputNS		= g_OutputTimeNS;

	Pipe->TimeBinNS		= 1e6;
	Pipe->TimeBinMax	= Pipe->OutputNS / Pipe->TimeBinNS;

	// stats histogram 
	Pipe->Stats.Time.BinPkt		= (u32*)malloc( sizeof(u32) * Pipe->TimeBinMax);
	Pipe->Stats.Time.BinByte	= (u32*)malloc( sizeof(u32) * Pipe->TimeBinMax);

	memset(Pipe->Stats.Time.BinPkt,  0, sizeof(u32) * Pipe->TimeBinMax);
	memset(Pipe->Stats.Time.BinByte, 0, sizeof(u32) * Pipe->TimeBinMax);

	g_TotalMemory += sizeof(u32) * Pipe->TimeBinMax;
	g_TotalMemory += sizeof(u32) * Pipe->TimeBinMax;

	lua_pushnumber(L, Index);

	return 1;
}

//-------------------------------------------------------------------------------------------------
// set a BPF filter 
int lpipe_bpfset(lua_State* L)
{
	/// pipeline to update
	u32 Index = lua_tonumber(L, -2);	
	Pipeline_t* Pipe = s_PipelineList[ Index ];

	// get BPF string from config file
	const u8* BPFString = lua_tostring(L, -1);	
	strncpy(Pipe->BPF, BPFString, sizeof(Pipe->BPF) );

	// parse BPF and generate bytecode/jit
	pcap_t* p = pcap_open_dead(1, 9232);
	assert(p != NULL);

	// compile it
	int ret = pcap_compile(p, (struct bpf_program*)Pipe->BPFCode, BPFString, 1, PCAP_NETMASK_UNKNOWN);

	// return codes are inverted 0 == success
	if (ret != 0)
	{
		char* Error = pcap_geterr(p);
		pcap_close(p);	

		printf("[%-40s] ERROR: bpf invalid (%s) : %s\n", Pipe->Name, BPFString, Error); 

		lua_pushstring(L, Error);
		return 1; 
	}
	pcap_close(p);	

	Pipe->BPFValid = true;

	// BPF code compiled 
	printf("[%-40s] set BPF (%s)\n", Pipe->Name, Pipe->BPF);

	return 0;
}

//-------------------------------------------------------------------------------------------------
// set burst rate 
int lpipe_burst(lua_State* L)
{
	/// pipeline to update
	u32 Index 			= lua_tonumber(L, -2);	
	Pipeline_t* Pipe 	= s_PipelineList[ Index ];

	// burst rate 
	u64 TimeBucketNS 	= lua_tonumber(L, -1);	
	if (TimeBucketNS <= 0)
	{
		printf("[%-40s] ERROR: set TimeBucket %lli nsec invalid\n", Pipe->Name, TimeBucketNS);
		lua_pushnumber(L, 1);
		return 0;
	}
	if (TimeBucketNS < 100e3)
	{
		printf("[%-40s] ERROR: set TimeBucket %lli nsec too low\n", Pipe->Name, TimeBucketNS);
		lua_pushnumber(L, 1);
		return 0;
	}

	Pipe->TimeBinNS 	= TimeBucketNS;
	Pipe->TimeBinMax	= Pipe->OutputNS / Pipe->TimeBinNS;

	// reallocate the time bin
	PipelineStats_t* PipeStats	= &Pipe->Stats; 
	if (Pipe->TimeBinMax > TIME_BIN_MAX)
	{
		printf("[%-40s] ERROR: set TimeBucket %lli nsec too small for current config (%i/%i)\n", Pipe->Name, Pipe->TimeBinNS, Pipe->TimeBinMax, TIME_BIN_MAX);
		lua_pushnumber(L, 1);
		return 1;
	}

	// reallocate bins
	free(PipeStats->Time.BinPkt);
	free(PipeStats->Time.BinByte);

	PipeStats->Time.BinPkt		= (u32*)malloc( sizeof(u32) * Pipe->TimeBinMax);
	PipeStats->Time.BinByte		= (u32*)malloc( sizeof(u32) * Pipe->TimeBinMax);

	assert(PipeStats->Time.BinPkt != NULL);
	assert(PipeStats->Time.BinByte != NULL);

	memset(PipeStats->Time.BinPkt,  0, sizeof(u32) * Pipe->TimeBinMax);
	memset(PipeStats->Time.BinByte, 0, sizeof(u32) * Pipe->TimeBinMax);

	g_TotalMemory += sizeof(u32) * Pipe->TimeBinMax;
	g_TotalMemory += sizeof(u32) * Pipe->TimeBinMax;

	// new microburst time bin set 
	printf("[%-40s] set TimeBucket %lli nsec Memory:%.2fMB\n", Pipe->Name, Pipe->TimeBinNS, g_TotalMemory/(float)kMB(1) );

	return 0;
}

//-------------------------------------------------------------------------------------------------
// create the output file 
int lpipe_output(lua_State* L)
{
	/// pipeline to update
	u32 Index = lua_tonumber(L, -2);	
	Pipeline_t* Pipe = s_PipelineList[ Index ];

	// get BPF string from config file
	const u8* FileName = lua_tostring(L, -1);	
	strncpy(Pipe->OutputFileName, FileName, sizeof(Pipe->OutputFileName) );

	// atteempt to open the filename
	Pipe->OutputFile = fopen(Pipe->OutputFileName, "a+");
	if (!Pipe->OutputFile)
	{
		printf("[%-40s] ERROR: failed to create output filename (%s)\n", Pipe->OutputFileName);

		lua_pushnumber(L, 1);
		return 1;
	}
	printf("[%-40s] created output filename (%s)\n", Pipe->Name, Pipe->OutputFileName);

	fprintf(Pipe->OutputFile, "# BPF Expression: (%s)\n", Pipe->BPF);
	fprintf(Pipe->OutputFile, "# Burst Bucket  : %16lli nsec\n", Pipe->TimeBinNS);
	fprintf(Pipe->OutputFile, "# Output Time   : %16lli nsec\n", Pipe->OutputNS);
	fprintf(Pipe->OutputFile, "# -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");

	fprintf(Pipe->OutputFile, "# %32s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s\n",
			"Time", 
			"EpochNS", 
			"Packets", 
			"Bytes", 
			"BurstMax(Mbps)", 
			"RateMean(Mbps)", 
			"PctTotal(Mbps)",
			"BurstMax(Pps)", 
			"RateMean(Pps)", 
			
			"RMON1_runt",
			"RMON1_64",
			"RMON1_64-127",
			"RMON1_128-255",
			"RMON1_256-511",
			"RMON1_512-1023",
			"RMON1_1024-1518",
			"RMON1_1024-2047",
			"RMON1_2048-4095",
			"RMON1_4096-8191",
			"RMON1_8192",

			"TCP.FIN",
			"TCP.SYN",
			"TCP.RST",
			"TCP.ACK",
			"TCP.PSH"
	);
	fflush(Pipe->OutputFile);

	return 0;
}

//-------------------------------------------------------------------------------------------------
// set the global output rate 
int lpipe_output_time(lua_State* L)
{
	// get BPF string from config file
	u64 OutputNS = lua_tonumber(L, -1);	

	if (OutputNS > 60e9)
	{
		printf("[%-40s] ERROR: Maximum output rate is 60sec\n", ""); 
		return 1;	
	}

	printf("[%-40s] Set Global output rate to %.3f sec\n", "", OutputNS/1e9);
	g_OutputTimeNS = OutputNS;

	return 0;
}

//-------------------------------------------------------------------------------------------------
// pipeline stats 
static PipelineStats_t* PipeStats_Alloc(u64 SeqNo)
{
	PipelineStats_t* Stats = NULL; 
	u32 Timeout = 0;
	while (true)
	{
		sync_lock(&s_PktBlockLock, 100);
		{
			Stats = s_PipeStatsFree;

			// has a freee entry?
			if (Stats != NULL)
			{
				Stats->SeqNo = SeqNo;
				s_PipeStatsFree = Stats->FreeNext;
			}
		}
		sync_unlock(&s_PktBlockLock);

		// sucessfull allocation
		if (Stats != NULL) break;

		// wait a bit
		usleep(0);
		if (Timeout++ > 100e3)
		{
			for (int i=0; i < s_PipelinePos; i++)
			{
				Pipeline_t* Pipe = s_PipelineList[i];	
				printf("[%3i] QueueDepth:%i\n", i, Pipe->QueueDepth);
			}
			assert(false);
		}
	}
	return Stats;
}

//-------------------------------------------------------------------------------------------------
// pipeline stats free 
static void PipeStats_Free(PipelineStats_t* PipeStats)
{
	sync_lock(&s_PktBlockLock, 100);
	{
		PipeStats->SeqNo	= 0;
		PipeStats->IsFlush	= false;

		PipeStats->Time.BinCnt = 0;

		PipeStats->Time.Pkt = 0;
		PipeStats->Time.Byte = 0;
		PipeStats->AllPkt = 0;
		PipeStats->AllByte = 0;
		memset(&PipeStats->Time.RMON1, 0, sizeof(PipeStats->Time.RMON1) );

		// clear tcp flag stats 
		PipeStats->TCPCnt_FIN 	= 0;
		PipeStats->TCPCnt_SYN 	= 0;
		PipeStats->TCPCnt_RST	= 0;
		PipeStats->TCPCnt_ACK 	= 0;
		PipeStats->TCPCnt_PSH 	= 0;

		// reset delta counters
		PipeStats->TotalPkt 	= 0;
		PipeStats->TotalByte 	= 0;

		// add to free stack
		PipeStats->FreeNext = s_PipeStatsFree;
		s_PipeStatsFree	= PipeStats;
	}
	sync_unlock(&s_PktBlockLock);
}

//-------------------------------------------------------------------------------------------------

void Pipeline_WriteLog(Pipeline_t* Pipe, u64 LastTS)
{
	u64 BytesMin = 1e12;
	u64 BytesMax = 0;

	u64 PktMin = 1e12;
	u64 PktMax = 0;

	u64 ByteS0	= 0;
	u64 ByteS1	= 0;
	u64 ByteS2	= 0;

	u64 PktS0	= 0;
	u64 PktS1	= 0;
	u64 PktS2	= 0;

	for (int i=0; i < Pipe->TimeBinMax; i++)
	{
		if (BytesMax < Pipe->Stats.Time.BinByte[i]) 
		{
			BytesMax = Pipe->Stats.Time.BinByte[i]; 
		}

		if (PktMax < Pipe->Stats.Time.BinPkt[i]) 
		{
			PktMax = Pipe->Stats.Time.BinPkt[i]; 
		}

		// calcualte mean / stdev 
		ByteS0	+= 1; 
		ByteS1 	+= Pipe->Stats.Time.BinByte[i];
		ByteS2 	+= Pipe->Stats.Time.BinByte[i] * Pipe->Stats.Time.BinByte[i];

		PktS0	+= 1; 
		PktS1 	+= Pipe->Stats.Time.BinPkt[i];
		PktS2 	+= Pipe->Stats.Time.BinPkt[i] * Pipe->Stats.Time.BinPkt[i];
	}

	u64 BpsMax  =  1e9 * (8.0 * (float)BytesMax) / (float)Pipe->TimeBinNS;
	u64 BpsMean = (1e9 *  8.0 * ByteS1)          / g_OutputTimeNS;

	u64 PpsMax  =  1e9 * ((float)PktMax) / (float)Pipe->TimeBinNS;
	u64 PpsMean = (1e9 * (float)PktS1)   / g_OutputTimeNS;

	float BytePct = Pipe->Stats.TotalByte * inverse(Pipe->Stats.AllByte);

	u8 DateTime[128];
	ns2str(DateTime, LastTS);

	fprintf(Pipe->OutputFile, "%32s, %20lli, %20lli, %20lli, %20.3f, %20.3f, %20.6f, %20lli, %20lli, %20i, %20i, %20i, %20i, %20i, %20i, %20i, %20i, %20i, %20i, %20i, %20i, %20i, %20i, %20i, %20i\n",
			DateTime,	
			LastTS,
			Pipe->Stats.TotalPkt,
			Pipe->Stats.TotalByte,
			BpsMax/1e6,	
			BpsMean/1e6,
			BytePct,

			PpsMax,	
			PpsMean,
		
			Pipe->Stats.Time.RMON1[RMON1_RUNT],
			Pipe->Stats.Time.RMON1[RMON1_64],
			Pipe->Stats.Time.RMON1[RMON1_64_127],
			Pipe->Stats.Time.RMON1[RMON1_128_255],
			Pipe->Stats.Time.RMON1[RMON1_256_511],
			Pipe->Stats.Time.RMON1[RMON1_512_1023],
			Pipe->Stats.Time.RMON1[RMON1_1024_1518],
			Pipe->Stats.Time.RMON1[RMON1_1024_1518] + Pipe->Stats.Time.RMON1[RMON1_1519_2047],
			Pipe->Stats.Time.RMON1[RMON1_2048_4095],
			Pipe->Stats.Time.RMON1[RMON1_4096_8191],
			Pipe->Stats.Time.RMON1[RMON1_8192],

			Pipe->Stats.TCPCnt_FIN,
			Pipe->Stats.TCPCnt_SYN,
			Pipe->Stats.TCPCnt_RST,
			Pipe->Stats.TCPCnt_ACK,
			Pipe->Stats.TCPCnt_PSH
	);

	fflush(Pipe->OutputFile);

	// reset the time buckets
	memset(Pipe->Stats.Time.BinPkt,  0, sizeof(u32) * Pipe->TimeBinMax );
	memset(Pipe->Stats.Time.BinByte, 0, sizeof(u32) * Pipe->TimeBinMax );

	Pipe->Stats.Time.Pkt = 0;
	Pipe->Stats.Time.Byte = 0;

	// RMON1 stats are not cumaltive
	memset(&Pipe->Stats.Time.RMON1, 0, sizeof(Pipe->Stats.Time.RMON1) );

	// total stats are cumulative
	Pipe->Stats.TotalPkt = 0;
	Pipe->Stats.TotalByte = 0;
}

//-------------------------------------------------------------------------------------------------
// close 
void Pipeline_Close(Pipeline_t* Pipe, u64 LastTS)
{
	fclose(Pipe->OutputFile);
	Pipe->OutputFile = NULL;
}

//-------------------------------------------------------------------------------------------------
// pipeline aggregate any stats generated
static void Pipeline_StatsAggregate(Pipeline_t* P)
{
	for (int j=0; j < 512; j++)
	{
		// free anything
		u32 UpdateCnt = 0;
		for (int cpu=0; cpu < g_CPUActive; cpu++)
		{
			PipelineStats_t* Stats = P->QueueHead[cpu];
			if (Stats == NULL) continue;

			// next seq no ?
			if (Stats->SeqNo != P->StatsSeqNo)
			{
				continue;
			}

			// decrement ptr 
			sync_lock(&P->QueueLock, 100);
			{
				P->QueueHead[cpu] = Stats->QueueNext;
				if (P->QueueHead[cpu] == NULL) P->QueueTail[cpu] = NULL; 
			}
			sync_unlock(&P->QueueLock);

			__sync_fetch_and_add(&P->QueueDepth, -1);

			// set last TS
			P->Stats.LastTS			= Stats->LastTS; 

			// update stats
			P->Stats.TotalPkt		+= Stats->TotalPkt;
			P->Stats.TotalByte		+= Stats->TotalByte;
			
			P->Stats.AllPkt			+= Stats->AllPkt;
			P->Stats.AllByte		+= Stats->AllByte;

			// update rmon stats
			P->Stats.Time.RMON1[RMON1_RUNT] 		+= Stats->Time.RMON1[RMON1_RUNT];
			P->Stats.Time.RMON1[RMON1_64] 			+= Stats->Time.RMON1[RMON1_64];
			P->Stats.Time.RMON1[RMON1_64_127]		+= Stats->Time.RMON1[RMON1_64_127];
			P->Stats.Time.RMON1[RMON1_128_255]		+= Stats->Time.RMON1[RMON1_128_255];
			P->Stats.Time.RMON1[RMON1_256_511]		+= Stats->Time.RMON1[RMON1_256_511];
			P->Stats.Time.RMON1[RMON1_512_1023]		+= Stats->Time.RMON1[RMON1_512_1023];
			P->Stats.Time.RMON1[RMON1_1024_1518]	+= Stats->Time.RMON1[RMON1_1024_1518];
			P->Stats.Time.RMON1[RMON1_1519_2047]	+= Stats->Time.RMON1[RMON1_1519_2047];
			P->Stats.Time.RMON1[RMON1_2048_4095]	+= Stats->Time.RMON1[RMON1_2048_4095];
			P->Stats.Time.RMON1[RMON1_4096_8191]	+= Stats->Time.RMON1[RMON1_4096_8191];

			// tcp stats
			P->Stats.TCPCnt_FIN						+= Stats->TCPCnt_FIN;
			P->Stats.TCPCnt_SYN						+= Stats->TCPCnt_SYN;
			P->Stats.TCPCnt_RST						+= Stats->TCPCnt_RST;
			P->Stats.TCPCnt_ACK						+= Stats->TCPCnt_ACK;
			P->Stats.TCPCnt_PSH						+= Stats->TCPCnt_PSH;

			// update histogram
			for (int i=0; i < Stats->Time.BinCnt; i++)
			{
				u32 Index 	  = Stats->Time.BinListIndex[i];
				u32 BytesWire = Stats->Time.BinListWire[i];

				P->Stats.Time.BinPkt[Index]  += 1;
				P->Stats.Time.BinByte[Index] += BytesWire;
			}

			// write log 
			if (Stats->IsFlush)
			{
				Pipeline_WriteLog(P, P->Stats.LastTS);
			}

			// release back to pool
			PipeStats_Free(Stats);

			// next seq no
			P->StatsSeqNo++;

			// activity counter 
			UpdateCnt++;	
		}

		// nothing more to update?
		if (UpdateCnt == 0) break;
	}
}

//-------------------------------------------------------------------------------------------------

static PacketBlock_t* PktBlock_Allocate(void)
{
	PacketBlock_t* PktBlock = NULL; 
	u32 Timeout = 0;
	while (true)
	{
		sync_lock(&s_PktBlockLock, 100);
		{
			PktBlock = s_PacketBlockFree;
			if (PktBlock != NULL)
			{
				s_PacketBlockFree		= PktBlock->FreeNext;
			}
		}
		sync_unlock(&s_PktBlockLock);

		// sucessfull allocation 
		if (PktBlock != NULL) break;

		// wait a bit
		usleep(0);
		assert(Timeout++ < 100e3);
	}

	return PktBlock; 
}

//-------------------------------------------------------------------------------------------------

void PktBlock_Free(PacketBlock_t* PktBlock)
{
	sync_lock(&s_PktBlockLock, 100);
	{
		// reset packet buffer
		PktBlock->PktCnt		= 0;
		PktBlock->ByteWire		= 0;
		PktBlock->ByteCapture	= 0;

		PktBlock->TSFirst		= 0;
		PktBlock->TSLast		= 0;

		PktBlock->BufferLength	= 0;

		PktBlock->FreeNext 		= s_PacketBlockFree;

		s_PacketBlockFree 		= PktBlock;
	}
	sync_unlock(&s_PktBlockLock);
}

//-------------------------------------------------------------------------------------------------

static void Pipeline_QueueDump(Pipeline_t* Pipe, u32 CPUID)
{
	u32 Depth = 0;
	PipelineStats_t* S = Pipe->QueueHead[CPUID];
	while (S != NULL)
	{
		printf("%3i : %p Seq: %i Pipe %i\n", Depth, S, S->SeqNo, Pipe->StatsSeqNo);
		S = S->QueueNext;
		Depth++;
	}
}

//-------------------------------------------------------------------------------------------------

static void Pipeline_QueueStats(Pipeline_t* Pipe, PipelineStats_t* Stats, u32 CPUID)
{
	Stats->QueueNext = NULL;

	sync_lock(&Pipe->QueueLock, 100);
	{
		// first entry
		if (Pipe->QueueTail[CPUID] == NULL)
		{
			Pipe->QueueHead[CPUID] = Stats;
			Pipe->QueueTail[CPUID] = Stats;
		}
		// add to tail
		else
		{
			Pipe->QueueTail[CPUID]->QueueNext 	= Stats;
			Pipe->QueueTail[CPUID] 				= Stats;
		}
	}
	sync_unlock(&Pipe->QueueLock);
	__sync_fetch_and_add(&Pipe->QueueDepth, 1);
}

//-------------------------------------------------------------------------------------------------
// process BPF filters on the block
static void PktBlock_Process(u32 CPUID, PacketBlock_t* PktBlock)
{
	// allocate pipeline stats 
	u32 TotalPkt		= 0;
	u32 TotalPktHit 	= 0;
	u32 TotalPktUnique 	= 0;

	// create stats block

	PipelineStats_t*	StatsList[128];

	for (int p=0; p < s_PipelinePos; p++)
	{
		StatsList[p] = PipeStats_Alloc(PktBlock->SeqNo); 
	}

	u64 LastTS			= 0;

	// process a block
	u32 Offset = 0;
	for (int i=0; i < PktBlock->PktCnt; i++)
	{
		FMADPacket_t* Pkt 	= (FMADPacket_t*)(PktBlock->Buffer + Offset);	
		Offset 				+= sizeof(FMADPacket_t);
		Offset 				+= Pkt->LengthCapture; 

		// pcap header for BPF parser
		struct pcap_pkthdr hdr;
		hdr.ts.tv_sec		= Pkt->TS / (u64)1e9;
		hdr.ts.tv_usec		= Pkt->TS % (u64)1e9;
		hdr.caplen			= Pkt->LengthCapture; 
		hdr.len				= Pkt->LengthWire;

		u8* PacketPayload	= (u8*)(Pkt + 1);

		// process all pipelines	
		for (int p=0; p < s_PipelinePos; p++)
		{
			Pipeline_t* Pipe 			= s_PipelineList[p];
			PipelineStats_t* PipeStats 	= StatsList[p]; 

			// time rounted within the update rate 
			u64 TimeSub = Pkt->TS % Pipe->OutputNS; 

			// time bin for this packet
			u64 TimeIndex = TimeSub / Pipe->TimeBinNS;

			// sanitize index
			if (TimeIndex >= Pipe->TimeBinMax)
			{
				printf("[%-40s] time index out of range %i\n", Pipe->Name, TimeIndex);
				TimeIndex = 0;
			}

			// update last TS of processed packet
			PipeStats->LastTS = Pkt->TS;

			// run BPF expression
			int Result = pcap_offline_filter((struct bpf_program*)Pipe->BPFCode, &hdr, (const u8*)PacketPayload);
			if (Result != 0)
			{
				// BPF got a hit
				PipeStats->TotalPkt		+= 1;
				PipeStats->TotalByte	+= Pkt->LengthWire;


				// update Bins
				PipeStats->Time.BinListIndex [PipeStats->Time.BinCnt] = TimeIndex;
				PipeStats->Time.BinListWire  [PipeStats->Time.BinCnt] = Pkt->LengthWire;
				PipeStats->Time.BinCnt++;

				// total stats
				PipeStats->Time.Pkt	+= 1;
				PipeStats->Time.Byte	+= Pkt->LengthWire;

				// update RMON stats
				u32 RMONIndex = Length2RMON1(Pkt->LengthWire);
				PipeStats->Time.RMON1[RMONIndex]++;

				// per protocol stats 
				{
					fEther_t* Ether = (fEther_t*)(Pkt + 1);	
					u8* Payload 	= (u8*)(Ether + 1);
					u16 EtherProto 	= swap16(Ether->Proto);

					// VLAN decoder
					if (EtherProto == ETHER_PROTO_VLAN)
					{
						VLANTag_t* Header 	= (VLANTag_t*)(Ether+1);
						u16* Proto 			= (u16*)(Header + 1);

						// update to the acutal proto / ipv4 header
						EtherProto 			= swap16(Proto[0]);
						Payload 			= (u8*)(Proto + 1);

						// VNTag unpack
						if (EtherProto == ETHER_PROTO_VNTAG)
						{
							VNTag_t* Header = (VNTag_t*)(Proto+1);
							Proto 			= (u16*)(Header + 1);

							// update to the acutal proto / ipv4 header
							EtherProto 		= swap16(Proto[0]);
							Payload 		= (u8*)(Proto + 1);
						}

						// is it double tagged ? 
						if (EtherProto == ETHER_PROTO_VLAN)
						{
							Header 			= (VLANTag_t*)(Proto+1);
							Proto 			= (u16*)(Header + 1);

							// update to the acutal proto / ipv4 header
							EtherProto 		= swap16(Proto[0]);
							Payload 		= (u8*)(Proto + 1);
						}
					}

					// MPLS decoder	
					if (EtherProto == ETHER_PROTO_MPLS)
					{
						MPLSHeader_t* MPLS = (MPLSHeader_t*)(Payload);

						// for now only process outer tag
						// assume there is a sane limint on the encapsulation count
						if (!MPLS->BOS)
						{
							MPLS += 1;
						}
						if (!MPLS->BOS)
						{
							MPLS += 1;
						}
						if (!MPLS->BOS)
						{
							MPLS += 1;
						}

						// update to next header
						if (MPLS->BOS)
						{
							EtherProto = ETHER_PROTO_IPV4;
							Payload = (u8*)(MPLS + 1);
						}
					}

					// ipv4 info
					if (EtherProto == ETHER_PROTO_IPV4)
					{
						IP4Header_t* IP4 = (IP4Header_t*)Payload;

						// IPv4 protocol decoders 
						u32 IPOffset = (IP4->Version & 0x0f)*4; 
						switch (IP4->Proto)
						{
						case IPv4_PROTO_TCP:
							{
								TCPHeader_t* TCP = (TCPHeader_t*)(Payload + IPOffset);

								PipeStats->TCPCnt_FIN  += TCP_FLAG_FIN(TCP->Flags);
								PipeStats->TCPCnt_SYN  += TCP_FLAG_SYN(TCP->Flags);
								PipeStats->TCPCnt_RST  += TCP_FLAG_RST(TCP->Flags);
								PipeStats->TCPCnt_ACK  += TCP_FLAG_ACK(TCP->Flags);
								PipeStats->TCPCnt_PSH  += TCP_FLAG_PSH(TCP->Flags);
							}
							break;
						case IPv4_PROTO_UDP:
							{
								UDPHeader_t* UDP = (UDPHeader_t*)(Payload + IPOffset);

							}
							break;
						}
					}
				}
				TotalPktHit++;
			}
			TotalPkt++;

			// time bin in comparsion 
			PipeStats->AllPkt 	+= 1;
			PipeStats->AllByte	+= Pkt->LengthWire;
		}

		LastTS 		= Pkt->TS;

		// write the per filter log files
		if (PktBlock->IsOutput && (LastTS > PktBlock->OutputTS))
		{
			// kick once 
			PktBlock->IsOutput = false; 

			// flag for flushing 
			for (int p=0; p < s_PipelinePos; p++)
			{
				StatsList[p]->IsFlush = true;

				// queue stats 
				Pipeline_QueueStats(s_PipelineList[p], StatsList[p], CPUID);

				// allocate new stats 
				StatsList[p] = PipeStats_Alloc(PktBlock->SeqNo+1); 
			}
		}
	}

	// queue 
	for (int p=0; p < s_PipelinePos; p++)
	{
		// queue stats 
		Pipeline_QueueStats(s_PipelineList[p], StatsList[p], CPUID);
	}
}

//-------------------------------------------------------------------------------------------------

void* PktBlock_Worker(void* User)
{
	u32 CPUID = __sync_fetch_and_add(&g_CPUActive, 1);

	printf("Start PktBlock Worker: %i\n", CPUID);
	while (!g_Exit)
	{
		u64 TSC0 = rdtsc();

		u32 Get = s_PacketBlockGet;	
		if (Get == s_PacketBlockPut)
		{
			usleep(0);
			continue;
		}

		// consume this block 
		if (__sync_bool_compare_and_swap(&s_PacketBlockGet, Get, Get + 1))
		{
			// block to process 
			PacketBlock_t* PktBlock = s_PacketBlockRing[ Get & s_PacketBlockMsk ];

			// run bpf filters on the block 
			PktBlock_Process(CPUID, PktBlock);

			// free the block
			PktBlock_Free(PktBlock);

			u64 TSC1 = rdtsc();
		}
	}
}

//-------------------------------------------------------------------------------------------------

int Parse_Start(void)
{
	u64 StartTS					= clock_ns();
	u64 PCAPOffset				= 0;

	FILE* FIn = stdin; 
	assert(FIn != NULL);

	// read header
	PCAPHeader_t HeaderMaster;
	int rlen = fread(&HeaderMaster, 1, sizeof(HeaderMaster), FIn);
	if (rlen != sizeof(HeaderMaster))
	{
		fprintf(stderr, "Failed to read pcap header\n");
		return 0;
	}
	PCAPOffset		= sizeof(PCAPHeader_t);

	bool IsPCAP = false;
	bool IsFMAD = false;
	u64 TScale = 0;
	switch (HeaderMaster.Magic)
	{
	case PCAPHEADER_MAGIC_NANO: fprintf(stderr, "PCAP Nano\n"); 	TScale = 1;     IsPCAP = true; break;
	case PCAPHEADER_MAGIC_USEC: fprintf(stderr, "PCAP Micro\n"); 	TScale = 1000; 	IsPCAP = true; break;
	case PCAPHEADER_MAGIC_FMAD: fprintf(stderr, "FMAD Chunked\n"); 	TScale = 1; 	IsFMAD = true; break;
	}

	u64 LastTS					= 0;
	u64 LastTSC					= 0;
	u64 NextOutputTS			= 0;
	u64 NextPrintTSC			= 0;

	// allocate packet blocks
	for (int i=0; i < s_PacketBlockMax; i++)
	{
		PacketBlock_t*	PktBlock	= (PacketBlock_t*)malloc(sizeof(PacketBlock_t));
		memset(PktBlock, 0, sizeof(PacketBlock_t));
		g_TotalMemory 			+= sizeof(PacketBlock_t);

		PktBlock->BufferMax		= kKB(256);
		PktBlock->Buffer		= malloc( PktBlock->BufferMax ); 
		assert(PktBlock->Buffer != 0);
		g_TotalMemory 			+= kKB(256); 

		PktBlock_Free(PktBlock);
	}
	fprintf(stderr, "PacketBlock TotalMemory: %.2f MB\n", g_TotalMemory / (float)kMB(1) );

	// allocate stats
	u32 TimeBinMax = g_OutputTimeNS / 100e3;
	fprintf(stderr, "Max Microburst Time resolution: %.2f Sec %i\n", g_OutputTimeNS / 1e9, TimeBinMax); 
	for (int i=0; i < s_PipeStatsListMax; i++)
	{
		PipelineStats_t* Stats 	= (PipelineStats_t*)malloc( sizeof(PipelineStats_t) );
		memset(Stats, 0, sizeof(PipelineStats_t));
		g_TotalMemory 			+= sizeof(PipelineStats_t);

		// allocate up to 100usec microburst level
		// each pipe can be configured differently but 100usec is the smallest resolution 
		Stats->Time.BinMax			= 4096;	
		Stats->Time.BinListIndex	= (u16*)malloc( sizeof(u16) * Stats->Time.BinMax);
		Stats->Time.BinListWire		= (u16*)malloc( sizeof(u16) * Stats->Time.BinMax);

		assert(Stats->Time.BinListIndex != NULL);
		assert(Stats->Time.BinListWire  != NULL);

		memset(Stats->Time.BinListIndex,  	0, sizeof(u16) * Stats->Time.BinMax);
		memset(Stats->Time.BinListWire, 	0, sizeof(u16) * Stats->Time.BinMax);

		g_TotalMemory += sizeof(u16) * Stats->Time.BinMax;
		g_TotalMemory += sizeof(u16) * Stats->Time.BinMax;

		// add to free queue
		PipeStats_Free(Stats);	
	}
	fprintf(stderr, "PipeStats TotalMemory: %.2f MB\n", g_TotalMemory / (float)kMB(1) );

	// create BPF processing threads
	u32 CPUCnt = 0;
	pthread_create(&s_PktBlockThread[0], NULL, PktBlock_Worker, (void*)NULL); CPUCnt++;
	pthread_create(&s_PktBlockThread[1], NULL, PktBlock_Worker, (void*)NULL); CPUCnt++;
	//pthread_create(&s_PktBlockThread[2], NULL, PktBlock_Worker, (void*)NULL); CPUCnt++;
	//pthread_create(&s_PktBlockThread[3], NULL, PktBlock_Worker, (void*)NULL); CPUCnt++;
	//pthread_create(&s_PktBlockThread[4], NULL, PktBlock_Worker, (void*)NULL); CPUCnt++;
	//pthread_create(&s_PktBlockThread[5], NULL, PktBlock_Worker, (void*)NULL); CPUCnt++;

	// set the main thread cpu
	cpu_set_t Thread0CPU;
	CPU_ZERO(&Thread0CPU);
	CPU_SET (g_CPUCore, &Thread0CPU);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &Thread0CPU);

	// set worker cpu mapping
	for (int i=0; i < CPUCnt; i++)
	{
		cpu_set_t Thread0CPU;
		CPU_ZERO(&Thread0CPU);
		CPU_SET (g_CPUWorker[i], &Thread0CPU);
		pthread_setaffinity_np(s_PktBlockThread[i], sizeof(cpu_set_t), &Thread0CPU);
	}

	u64   StreamCAT_BytePending	= 0;
	float StreamCAT_CPUActive	= 0;
	float StreamCAT_CPUFetch	= 0;
	float StreamCAT_CPUSend		= 0;

	u64 TotalPktUnique			= 0;		// total number of unique packets
	u64 TotalPkt				= 0;		// total number of packets processed
	u64 TotalPktHit				= 0;		// total number of packets that hit a BPF filter

	u32 StatsIndex				= 0;		// current stats index
	u64 SeqNo					= 0;		// pkt block sequence number. 

	while (!feof(FIn))
	{
		fProfile_Start(0, "Core Top");

		// allocate packet block 
		fProfile_Start(3, "PacketBlock Alloc");

		PacketBlock_t* PktBlock = PktBlock_Allocate();

		fProfile_Stop(3);

		// old style pcap
		if (IsPCAP)
		{
			while (PktBlock->BufferLength < PktBlock->BufferMax - kKB(16))
			{
				PCAPPacket_t*	PktHeader	= (PCAPPacket_t*)(PktBlock->Buffer + PktBlock->BufferLength);
				
				// header
				int rlen = fread(PktHeader, 1, sizeof(PCAPPacket_t), FIn);
				if (rlen != sizeof(PCAPPacket_t)) break;

				// validate size
				if ((PktHeader->LengthCapture == 0) || (PktHeader->LengthCapture > 128*1024)) 
				{
					fprintf(stderr, "Invalid packet length: %i\n", PktHeader->LengthCapture);
					break;
				}

				// payload
				rlen = fread(PktHeader + 1, 1, PktHeader->LengthCapture, FIn);
				if (rlen != PktHeader->LengthCapture)
				{
					fprintf(stderr, "payload read fail %i expect %i\n", rlen, PktHeader->LengthCapture);
					break;
				}

				u64 TS 				= (u64)PktHeader->Sec * 1000000000ULL + (u64)PktHeader->NSec * TScale;
				u32 LengthWire 		= PktHeader->LengthWire;
				u32 LengthCapture 	= PktHeader->LengthCapture;
				u32 PortNo			= 0;

				// in-place conversion to FMAD Packet 
				FMADPacket_t* PktFMAD	= (FMADPacket_t*)PktHeader;
				PktFMAD->TS				= TS;
				PktFMAD->PortNo			= 0;
				PktFMAD->Flag			= 0;
				PktFMAD->LengthWire		= LengthWire;
				PktFMAD->LengthCapture	= LengthCapture;

				// next in packet block
				PktBlock->BufferLength += sizeof(PCAPPacket_t) + LengthCapture;

				// time range 
				if (PktBlock->TSFirst == 0) PktBlock->TSFirst = TS;
				PktBlock->TSLast = TS;

				PktBlock->PktCnt		+= 1;
				PktBlock->ByteWire		+= LengthWire; 
				PktBlock->ByteCapture	+= LengthCapture;
			}
		}

		// FMAD chunked format 
		if (IsFMAD)
		{
			FMADHeader_t Header;
			int rlen = fread(&Header, 1, sizeof(Header), FIn);
			if (rlen != sizeof(Header))
			{
				fprintf(stderr, "FMADHeader read fail: %i %i : %i\n", rlen, sizeof(Header), errno, strerror(errno));
				break;
			}

			// sanity checks
			assert(Header.Length < 1024*1024);
			assert(Header.PktCnt < 1e6);

			rlen = fread(PktBlock->Buffer, 1, Header.Length, FIn);
			if (rlen != Header.Length)
			{
				fprintf(stderr, "FMADHeader payload read fail: %i %i : %i\n", rlen, Header.Length, errno, strerror(errno));
				break;
			}

			PktBlock->PktCnt		= Header.PktCnt; 
			PktBlock->ByteWire		= Header.BytesWire;
			PktBlock->ByteCapture	= Header.BytesCapture;
			PktBlock->TSFirst		= Header.TSStart;
			PktBlock->TSLast		= Header.TSEnd;
			PktBlock->BufferLength	= Header.Length;

			StreamCAT_BytePending = Header.BytePending;
			StreamCAT_CPUActive   = Header.CPUActive / (float)0x10000;
			StreamCAT_CPUFetch    = Header.CPUFetch / (float)0x10000;
			StreamCAT_CPUSend     = Header.CPUSend / (float)0x10000;
		}

		// update stats
		PCAPOffset 		+= PktBlock->BufferLength; 
		TotalPktUnique	+= PktBlock->PktCnt;

		PktBlock->SeqNo	= SeqNo++;

		// first timestamp
		if (NextOutputTS == 0)
		{
			NextOutputTS 	= (u64)(PktBlock->TSFirst / g_OutputTimeNS);
			NextOutputTS 	+= 1; 											// output at next boundary
			NextOutputTS 	*= g_OutputTimeNS;
		}

		// is this an output block
		PktBlock->IsOutput	= false;
		if (PktBlock->TSLast > NextOutputTS)
		{
			PktBlock->IsOutput	= true;
			PktBlock->OutputTS 	= NextOutputTS;

			// print every 60sec
			// jump to next block, e.g if there are X periods of g_OutputTimeNS
			// without any packets skip them
			u64 NextIndex 		= PktBlock->TSLast / g_OutputTimeNS;
			NextOutputTS 		= (NextIndex + 1) * g_OutputTimeNS;

			// add seq gap for split packet block
			SeqNo++;
		}

		// update last known TS 
		if (PktBlock->PktCnt > 0) LastTS = PktBlock->TSLast;

		// stall untill theres space
		fProfile_Start(2, "PacketBlock Queue");
		while ((s_PacketBlockPut  - s_PacketBlockGet) > (s_PacketBlockMsk+1) - 16)
		{
			usleep(0);
		}
		fProfile_Stop(2);

		// push to processing queue
		s_PacketBlockRing[ s_PacketBlockPut & s_PacketBlockMsk ] = PktBlock;
		s_PacketBlockPut++;

		// run single threaded 
		//PktBlock_Process(0, PktBlock);
		//PktBlock_Free(PktBlock);

		// aggreate pipeline stats
		fProfile_Start(1, "Aggregate");
		for (int i=0; i < s_PipelinePos; i++)
		{
			Pipeline_StatsAggregate(s_PipelineList[i]);
		}
		fProfile_Stop(1);

		// write processing status 
		u64 TSC = rdtsc();
		if (TSC > NextPrintTSC)
		{
			NextPrintTSC = TSC + 3e9; 

			u8 TimeStr[1024];
			clock_date_t c	= ns2clock(LastTS);
			sprintf(TimeStr, "%04i-%02i-%02i %02i:%02i:%02i", c.year, c.month, c.day, c.hour, c.min, c.sec);

			double dT = (clock_ns() - StartTS) / 1e9;
			double Bps = (PCAPOffset * 8.0) / dT; 
			double Pps = (TotalPktUnique) / dT; 

			u32 QueueDepth = s_PipelineList[0]->QueueDepth;

			fprintf(stderr, "[%.3f H][%s] : Total Bytes %.3f GB Speed: %.3fGbps %.3f Mpps StreamCat: %6.2f MB Fetch %.2f Send %.2f : P0 QueueDepth:%i\n", 
						dT / (60*60), 
						TimeStr, 
						PCAPOffset / 1e9, 
						Bps / 1e9, 
						Pps / 1e6, 
						StreamCAT_BytePending / (float)kMB(1), 
						StreamCAT_CPUFetch,
						StreamCAT_CPUSend,
						
						QueueDepth);
			fflush(stderr);
			fflush(stdout);

			static int cnt = 0;
			if (cnt++ > 10)
			{
				cnt = 0;
				fProfile_Dump(0);
			}
		}

		fProfile_Stop(0);
	}

	// wait for all blocks have completed
	while (s_PacketBlockGet != s_PacketBlockPut)
	{
		usleep(1000);
	}

	// signal threads to exit and wait 
	g_Exit = true;
	for (int i=0; i < CPUCnt; i++)
	{
		pthread_join(s_PktBlockThread[i], 0);
	}

	// aggreate after final processing 
	for (int i=0; i < s_PipelinePos; i++)
	{
		Pipeline_StatsAggregate(s_PipelineList[i]);
	}

	// flush any remaining stats 
	for (int p=0; p < s_PipelinePos; p++)
	{
		Pipeline_t* Pipe = s_PipelineList[p];
		Pipeline_WriteLog(Pipe, LastTS);
	}

	// flush pipe with last log
	for (int p=0; p < s_PipelinePos; p++)
	{
		Pipeline_t* Pipe = s_PipelineList[p];
		Pipeline_Close(Pipe, LastTS);
	}

	printf("TotalPktUnique : %10lli\n", TotalPktUnique);
	printf("TotalPkt       : %10lli\n", TotalPkt);
	printf("TotalPktHit    : %10lli\n", TotalPktHit);

	printf("Total Time     : %.f Sec\n", (clock_ns() - StartTS) / 1e9);

	return 0;
}

static void lua_register_pipe(lua_State* L, const char* FnName, lua_CFunction Func)
{
	lua_getglobal(L, "pipe");
	assert(!lua_isnil(L, -1));

	lua_pushcfunction(L, Func);
	lua_setfield(L, -2, FnName); 
}

//-------------------------------------------------------------------------------------------------

void Parse_Open(lua_State* L)
{
	lua_newtable(L);
	lua_setglobal(L, "pipe");

	lua_register_pipe(L, "create",			lpipe_create);
	lua_register_pipe(L, "bpf",				lpipe_bpfset);
	lua_register_pipe(L, "burst",			lpipe_burst);
	lua_register_pipe(L, "output",			lpipe_output);
	lua_register_pipe(L, "output_time",		lpipe_output_time);
}
