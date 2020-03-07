//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2018, fmad engineering llc 
//
// input parser 
//
// run each BPF filter
//
// sudo /opt/fmadio/bin/stream_cat --uid bpfcounter_1583488028395397888  --cpu 9  --chunked --pktslice 96 --ignore_fcs interop17_20200301_1838 |  ./pcap_bpfcounter  --cpu-core 10 --cpu-output 1 11 --cpu-pipe 12 12 13 14 15 16 17 18 19 20 21 22 23 --config /opt/fmadio/etc/bpfcounter.lua
//
// rule set is 100 MAC address bpf filters 			 		
//
// ----------------------------------------------------------------------------
// for i=0,100 do
// 	-- create pipelines
// 	Pipe_Create(
// 	{
// 		["Name"] 			= "full"..i,
// 		["BPF"]  			= "ether src 11:11:11:11:11:11",
// 		["RE"]   			= "",
// 		["JSON"] 			= '"EtherSrc":"00:00:00:00:00:00","EtherDst":"11:11:11:11:11:11"',
// 	})
// end
//
// Output mode is NULL
//
// 2020/03/06 : baseline performance stats. linux pipe mode chunked 
//
//				20200306_19-44-01 Performance : 45.216 sec  9.49 GB 1.679 Gbps 1.919Mpps 	
//
// 				baseline performance stats. linux pipe mode 
//
// 				20200306_19-40-34 Performance : 52.930 sec  9.49 GB 1.434 Gbps 1.640Mpps
//
// 2020/03/06 : moved to SHMRing bufer. some performance increase ~ 30% but not that good.. 
//
//              20200306_20-16-16 Performance : 35.586 sec  9.49 GB 2.134 Gbps 2.439Mpps
//
// 2020/03/06 : added fast path ether src/dst filters
//
//              (before without fast path) buffers bit bigger than previous test
//              20200307_01-46-50 Performance : 28.307 sec  9.49 GB 2.682 Gbps 3.066Mpps
//
//              (with fast path)
//              20200307_01-45-45 Performance : 20.207 sec  9.49 GB 3.757 Gbps 4.295Mpps
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
#include "output.h"
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

	u64				OutputTS;						// timestamp of this output block 
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


typedef struct Pipeline_t
{
	// rule definition 
	u8						Name[256];					// string name of the expression

	// output files
	u64						OutputNS;					// nanos between outputs 
	u8*						OutputJSON;					// additional JSON line settings 


	bool					BPFValid;					// BPF expression compiled sucessfully
	u8						BPF[1024];
	u8						BPFCode[16*1024];

	// fast path mac src filter 
	bool					FilterMACSrcEnb;			// src mac filter enabled	
	u8						FilterMACSrc[6];			// src mac address to filter on

	bool					FilterMACDstEnb;			// dst mac filter enabled	
	u8						FilterMACDst[6];			// dst mac address to filter on

	u32						TimeBinMax;					// max bins
	u64						TimeBinNS;					// time bin in nanos	

	u64						StatsSeqNo;					// next stats seq no to update
	PipelineStats_t			Stats;						// current aggregated stats 
													// for the pipeline 

	u32						QueueLock;					// mutual exclusion access to the queue
	s32						QueueDepth;					// depth of the queue
	PipelineStats_t*		QueueHead[32];				// one queue head per cpu 
	PipelineStats_t*		QueueTail[32];				// one queue head per cpu 

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

static u32				s_PacketBlockMax	= 256;		// number of blocks to allocate

static volatile u32		s_PacketBlockPut	= 0;		// packet blocks ready for processing	
static volatile u32		s_PacketBlockGet	= 0;		// packet blocks completed processing
static volatile u32		s_PacketBlockMsk	= 0x7f;		// 
static PacketBlock_t*	s_PacketBlockRing[1024];			// packet block queue

static PipelineStats_t*	s_PipeStatsFree		= NULL;		// free stats list
static u32				s_PipeStatsListMax	= 16*1024;	// number of stats entries to allocate 
static u32				s_PipeStatsLock		= 0;		// mutual exclusion for alloc/free

u64						g_TotalMemory		= 0;		// total memory allocated

u32						g_CPUCore			= 15;		// main cpu mapping
u32						g_CPUWorkerCnt		= 4;		// number of CPU worker BPF threads 
u32						g_CPUWorker[32]		= {20, 21, 22, 23};
u32						g_CPUActive			= 1;		// number of worker cpus active

volatile bool			g_Exit				= false;	// global exit request

static pthread_t   		s_PktBlockThread[16];			// worker decode thread list
static u32				s_PktBlockLock		= 0;		// mutual exculsion for alloc/free

static u8				s_JSONBuffer[128*1024];				// line buffer for flushing stats output
static u8*				s_JSONLine			= NULL;			// current output position 

u8						g_CaptureName[256] 	= { 0 };
u8						g_DeviceName[256];

bool 					g_Verbose			= false;

static u64				s_PipeWorkerCPUTotal[128];		// total cpu cycles for the worker
static u64				s_PipeWorkerCPU[128];			// cpu cycles spent operating on data 
static u64				s_PipeWorkerCPUAlloc[128];		// cpu cycles spent allocating buffers 

static volatile bool	s_PipeWorkerCPUReset[128];		// request to reset the stats 


static struct Output_t*	s_Output			= NULL;		// output interface to use 

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
// manually set device name 
void Global_SetDeviceName(u8* DeviceName)
{
	strncpy(g_DeviceName, DeviceName, sizeof(g_DeviceName));
	fprintf(stderr, "Set DeviceName [%s]\n", g_DeviceName);
}

//-------------------------------------------------------------------------------------------------
// create a new pipeline 
struct Pipeline_t*  Pipe_Create(u8* Name)
{
	Pipeline_t*		Pipe = (Pipeline_t*)malloc( sizeof(Pipeline_t) );
	memset(Pipe, 0, sizeof(Pipeline_t));
	g_TotalMemory += sizeof(Pipeline_t);

	u32 Index 				= s_PipelinePos++;	
	s_PipelineList[Index]	= Pipe;

	strncpy(Pipe->Name, Name, sizeof(Pipe->Name) );

	fprintf(stderr, "[%-40s] create a pipeline\n", Pipe->Name);

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

	return Pipe;
}

//-------------------------------------------------------------------------------------------------
// set a BPF filter 
int Pipe_SetBPF(struct Pipeline_t* Pipe, u8* BPFString)
{
	// get BPF string from config file
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

		fprintf(stderr, "[%-40s] ERROR: bpf invalid (%s) : %s\n", Pipe->Name, BPFString, Error); 

		return -1; 
	}
	pcap_close(p);	

	Pipe->BPFValid = true;

	// BPF code compiled 
	fprintf(stderr, "[%-40s] set BPF \"%s\"\n", Pipe->Name, Pipe->BPF);

	return 0;
}

//-------------------------------------------------------------------------------------------------
// set fast path MAC Src filter
int Pipe_SetFastFilterMACSrc(struct Pipeline_t* Pipe, u8 MAC0, u8 MAC1, u8 MAC2, u8 MAC3, u8 MAC4, u8 MAC5)
{

	Pipe->FilterMACSrcEnb = true;
	Pipe->FilterMACSrc[0] = MAC0;
	Pipe->FilterMACSrc[1] = MAC1;
	Pipe->FilterMACSrc[2] = MAC2;
	Pipe->FilterMACSrc[3] = MAC3;
	Pipe->FilterMACSrc[4] = MAC4;
	Pipe->FilterMACSrc[5] = MAC0;

	fprintf(stderr, "[%-40s] MACSrcFilter %02x:%02x:%02x:%02x:%02x:%02x\n", Pipe->Name, MAC0, MAC1, MAC2, MAC3, MAC4, MAC5);

	return 0;
}

//-------------------------------------------------------------------------------------------------
// set fast path MAC Dst filter
int Pipe_SetFastFilterMACDst(struct Pipeline_t* Pipe, u8 MAC0, u8 MAC1, u8 MAC2, u8 MAC3, u8 MAC4, u8 MAC5)
{

	Pipe->FilterMACDstEnb = true;
	Pipe->FilterMACDst[0] = MAC0;
	Pipe->FilterMACDst[1] = MAC1;
	Pipe->FilterMACDst[2] = MAC2;
	Pipe->FilterMACDst[3] = MAC3;
	Pipe->FilterMACDst[4] = MAC4;
	Pipe->FilterMACDst[5] = MAC0;

	fprintf(stderr, "[%-40s] MACDstFilter %02x:%02x:%02x:%02x:%02x:%02x\n", Pipe->Name, MAC0, MAC1, MAC2, MAC3, MAC4, MAC5);

	return 0;
}

//-------------------------------------------------------------------------------------------------
// set burst rate 
int Pipe_SetBurstTime(struct Pipeline_t* Pipe, double TimeBucketNS)
{
	// burst rate 
	if (TimeBucketNS <= 0)
	{
		fprintf(stderr, "[%-40s] ERROR: set TimeBucket %lli nsec invalid\n", Pipe->Name, TimeBucketNS);
		return 0;
	}
	if (TimeBucketNS < 100e3)
	{
		fprintf(stderr, "[%-40s] ERROR: set TimeBucket %lli nsec too low\n", Pipe->Name, TimeBucketNS);
		return 0;
	}

	Pipe->TimeBinNS 	= TimeBucketNS;
	Pipe->TimeBinMax	= Pipe->OutputNS / Pipe->TimeBinNS;

	// reallocate the time bin
	PipelineStats_t* PipeStats	= &Pipe->Stats; 
	if (Pipe->TimeBinMax > TIME_BIN_MAX)
	{
		fprintf(stderr, "[%-40s] ERROR: set TimeBucket %lli nsec too small for current config (%i/%i)\n", Pipe->Name, Pipe->TimeBinNS, Pipe->TimeBinMax, TIME_BIN_MAX);
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
	fprintf(stderr, "[%-40s] set TimeBucket %lli nsec Memory:%.2fMB\n", Pipe->Name, Pipe->TimeBinNS, g_TotalMemory/(float)kMB(1) );

	return 0;
}


//-------------------------------------------------------------------------------------------------
// set any user defined JSON 
void Pipe_SetUserJSON(struct Pipeline_t* Pipe, u8* UserJSON)
{
	// inlcude user defined JSON in the bulk upload 
	Pipe->OutputJSON = strdup(UserJSON);

	fprintf(stderr, "[%-40s] User JSON \"%s\"\n", Pipe->Name, UserJSON);
}


//-------------------------------------------------------------------------------------------------
// set the global output rate 
int Pipe_SetUpdateRate(double OutputNS)
{
	if (OutputNS > 60e9)
	{
		fprintf(stderr, "[%-40s] ERROR: Maximum output rate is 60sec\n", ""); 
		return 1;	
	}

	fprintf(stderr, "Set Global output rate to %.3f sec\n", OutputNS/1e9);
	g_OutputTimeNS = OutputNS;

	return 0;
}

//-------------------------------------------------------------------------------------------------
// renames the capture name 
void Pipe_SetCaptureName(u8* CaptureName)
{
	sprintf(g_CaptureName, "%s", CaptureName); 

	fprintf(stderr, "Update CaptureName [%s]\n", g_CaptureName);
}

//-------------------------------------------------------------------------------------------------
// set output object 
int Pipe_SetOutput(struct Output_t* O)
{
	s_Output = O;

	return 0;
}


//-------------------------------------------------------------------------------------------------
// set cpu core 
void Pipe_SetCPUCore(int CPU) 
{
	g_CPUCore = CPU;
	fprintf(stderr, "   Pipe Core CPU %i\n", g_CPUCore);
}

//-------------------------------------------------------------------------------------------------
// set number of worker threads and mapping 
void Pipe_SetCPUWorker(int CPUCnt, u32* CPUMap)
{
	fprintf(stderr, "   Pipe Woker CPU Cnt %i [", CPUCnt);
	g_CPUWorkerCnt = CPUCnt;
	for (int i=0; i < CPUCnt; i++)
	{
		fprintf(stderr, "%i ", CPUMap[i]);
		g_CPUWorker[i] = CPUMap[i];
	}
	fprintf(stderr, "]\n");
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
			printf("StatsFree: %p SeqNo:%i\n", s_PipeStatsFree, SeqNo);
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
	assert(PipeStats != NULL);
	sync_lock(&s_PktBlockLock, 100);
	{
		PipeStats->SeqNo		= 0;
		PipeStats->IsFlush		= false;
		PipeStats->OutputTS		= 0;

		PipeStats->Time.BinCnt 	= 0;

		PipeStats->Time.Pkt 	= 0;
		PipeStats->Time.Byte 	= 0;
		PipeStats->AllPkt 		= 0;
		PipeStats->AllByte 		= 0;
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

void Pipeline_WriteLog(Pipeline_t* Pipe, u64 OutputTS)
{
	u64 BytesMin = 1e12;
	u64 BytesMax = 0;

	u64 PktMin 	= 1e12;
	u64 PktMax 	= 0;

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

	//u8 DateTime[128];
	//ns2str(DateTime, LastTS);

	// append to the output block
	u8* JSON = s_JSONLine;

	// include bulk upload header
	JSON += sprintf(JSON, "{\"index\":{\"_index\":\"%s\",\"_score\":null}}\n", g_CaptureName);

	// JSON line
	JSON += sprintf(JSON, "{");
	JSON += sprintf(JSON, "\"Name\":\"%s\",", 		Pipe->Name);					// name of the pipeline from config 
	JSON += sprintf(JSON, "\"Device\":\"%s\",", 	g_DeviceName);					// device name 
	JSON += sprintf(JSON, "\"timestamp\":%lli,", 	OutputTS / 1000000ULL);			// timestamp must be in msec
	JSON += sprintf(JSON, "\"TotalPkt\":%lli,", 	Pipe->Stats.TotalPkt); 
	JSON += sprintf(JSON, "\"TotalByte\":%lli,", 	Pipe->Stats.TotalByte); 
	JSON += sprintf(JSON, "\"TotalBits\":%lli,", 	Pipe->Stats.TotalByte * 8); 
	JSON += sprintf(JSON, "\"BytePct\":%f,", 		BytePct); 

	JSON += sprintf(JSON, "\"BpsMax\":%lli,",  		BpsMax);
	JSON += sprintf(JSON, "\"BpsMean\":%lli,",  	BpsMean);

	JSON += sprintf(JSON, "\"PpsMax\":%lli,",  		PpsMax);
	JSON += sprintf(JSON, "\"PpsMean\":%lli",  		PpsMean);

	// append any user defined JSON fields 
	if (Pipe->OutputJSON != NULL)
	{
		JSON += sprintf(JSON, ",%s",  		Pipe->OutputJSON);
	}

	JSON += sprintf(JSON, "}\n");

	s_JSONLine = JSON;

	// reset the time buckets
	memset(Pipe->Stats.Time.BinPkt,  0, sizeof(u32) * Pipe->TimeBinMax );
	memset(Pipe->Stats.Time.BinByte, 0, sizeof(u32) * Pipe->TimeBinMax );

	Pipe->Stats.Time.Pkt = 0;
	Pipe->Stats.Time.Byte = 0;

	// RMON1 stats are not cumaltive
	memset(&Pipe->Stats.Time.RMON1, 0, sizeof(Pipe->Stats.Time.RMON1) );

	// total stats are cumulative
	Pipe->Stats.TotalPkt 	= 0;
	Pipe->Stats.TotalByte 	= 0;
	Pipe->Stats.AllByte 	= 0;
}

//-------------------------------------------------------------------------------------------------
// close 
void Pipeline_Close(Pipeline_t* Pipe, u64 LastTS)
{
}

//-------------------------------------------------------------------------------------------------
// pipeline aggregate any stats generated
static bool Pipeline_StatsAggregate(Pipeline_t* P)
{
	// assume JSON entry is being output
	bool IsFlush = false; 

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
			P->Stats.LastTS							= Stats->LastTS; 
			P->Stats.OutputTS						= (Stats->OutputTS != 0) ? Stats->OutputTS : P->Stats.OutputTS; 

			// update stats
			P->Stats.TotalPkt						+= Stats->TotalPkt;
			P->Stats.TotalByte						+= Stats->TotalByte;
			
			P->Stats.AllPkt							+= Stats->AllPkt;
			P->Stats.AllByte						+= Stats->AllByte;

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
				IsFlush = true;
				Pipeline_WriteLog(P, P->Stats.OutputTS);
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

	return IsFlush;
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
			int Result = 0; 

			if (Pipe->BPFValid)
			{
				Result =  pcap_offline_filter((struct bpf_program*)Pipe->BPFCode, &hdr, (const u8*)PacketPayload);
			}

			// hardcoded mac src filter
			if (Pipe->FilterMACSrcEnb)
			{
				fEther_t* Ether = (fEther_t*)(Pkt + 1);
				if ((Ether->Src[0] == Pipe->FilterMACSrc[0]) &&
					(Ether->Src[1] == Pipe->FilterMACSrc[1]) &&
					(Ether->Src[1] == Pipe->FilterMACSrc[2]) &&
					(Ether->Src[1] == Pipe->FilterMACSrc[3]) &&
					(Ether->Src[1] == Pipe->FilterMACSrc[4]) &&
					(Ether->Src[1] == Pipe->FilterMACSrc[5]))
				{
					Result = 1;
				}
			}

			// hardcoded mac dst filter
			if (Pipe->FilterMACSrcEnb)
			{
				fEther_t* Ether = (fEther_t*)(Pkt + 1);
				if ((Ether->Dst[0] == Pipe->FilterMACDst[0]) &&
					(Ether->Dst[1] == Pipe->FilterMACDst[1]) &&
					(Ether->Dst[1] == Pipe->FilterMACDst[2]) &&
					(Ether->Dst[1] == Pipe->FilterMACDst[3]) &&
					(Ether->Dst[1] == Pipe->FilterMACDst[4]) &&
					(Ether->Dst[1] == Pipe->FilterMACDst[5]))
				{
					Result = 1;
				}
			}

			//int Result = 0; 
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
				StatsList[p]->OutputTS = PktBlock->OutputTS;

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

	fprintf(stderr, "Start PktBlock Worker: %i\n", CPUID);
	while (!g_Exit)
	{
		u64 TSC0 = rdtsc();

		u32 Get = s_PacketBlockGet;	
		if (Get == s_PacketBlockPut)
		{
			usleep(0);
		}
		else
		{
			// consume this block 
			if (__sync_bool_compare_and_swap(&s_PacketBlockGet, Get, Get + 1))
			{
				u64 TSC2 = rdtsc();

				// block to process 
				PacketBlock_t* PktBlock = s_PacketBlockRing[ Get & s_PacketBlockMsk ];

				// run bpf filters on the block 
				PktBlock_Process(CPUID, PktBlock);

				// free the block
				PktBlock_Free(PktBlock);

				// profiling
				u64 dTSC = rdtsc() - TSC2;
				s_PipeWorkerCPU[CPUID] += dTSC;
			}
		}

		// total CPU cycles worker has used
		u64 dTSC = rdtsc() - TSC0;
		s_PipeWorkerCPUTotal[CPUID] += dTSC;
		if (s_PipeWorkerCPUReset[CPUID])
		{
			s_PipeWorkerCPUReset[CPUID] = false;
			s_PipeWorkerCPU		[CPUID] = 0;
			s_PipeWorkerCPUAlloc[CPUID] = 0;
			s_PipeWorkerCPUTotal[CPUID] = 0;
		}
	}
}

//-------------------------------------------------------------------------------------------------

int Parse_Start(void)
{
	u64 PCAPOffset				= 0;

	// get the hosts name
	gethostname(g_DeviceName, sizeof(g_DeviceName));	

	u8 ClockStr[128];
	clock_str(ClockStr, clock_date() );

	// if capture name not written by config
	if (g_CaptureName[0] == 0)
	{
		sprintf(g_CaptureName, "%s-bpfcounter_%s", g_DeviceName, ClockStr); 
	}


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

	bool IsPCAP 	= false;
	bool IsFMAD 	= false;
	bool IsFMADRING = false;
	u64 TScale = 0;

	switch (HeaderMaster.Magic)
	{
	case PCAPHEADER_MAGIC_NANO: 
		fprintf(stderr, "PCAP Nano\n"); 
		TScale = 1;    
		IsPCAP = true;
		break;
	case PCAPHEADER_MAGIC_USEC: 
		fprintf(stderr, "PCAP Micro\n");
		TScale = 1000; 
		IsPCAP = true;
		break;

	case PCAPHEADER_MAGIC_FMAD: 
		fprintf(stderr, "FMAD Format Chunked\n");
		TScale = 1; 
		IsFMAD = true;
		break;

	case PCAPHEADER_MAGIC_FMADRING: 
		fprintf(stderr, "FMAD Ringbuffer Chunked\n");
		TScale = 1; 
		IsFMADRING = true;
		break;


	default:
		fprintf(stderr, "invaliid PCAP format %08x\n", HeaderMaster.Magic);
		return -1;
	}
	// SHM ring format
	FMADSHMRingHeader_t* SHMRingHeader	= NULL; 
	u8* SHMRingData						= NULL; 
	if (IsFMADRING)
	{
		// stream cat sends the size of the shm file
		u64 SHMRingSize = 0;
		fread(&SHMRingSize, 1, sizeof(SHMRingSize), FIn);

		u8 SHMRingName0[128];			// stream_cat sends ring names in 128B
		u8 SHMRingName1[128];			// stream_cat sends ring names in 128B
		u8 SHMRingName2[128];			// stream_cat sends ring names in 128B
		u8 SHMRingName3[128];			// stream_cat sends ring names in 128B

		fread(SHMRingName0, 1, 128, FIn);
		fread(SHMRingName1, 1, 128, FIn);
		fread(SHMRingName2, 1, 128, FIn);
		fread(SHMRingName3, 1, 128, FIn);

		fprintf(stderr, "SHMRingName [%s] %lli\n", SHMRingName0, SHMRingSize);

		// open the shm ring
		int fd = shm_open(SHMRingName0, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
		if (fd < 0)
		{
			fprintf(stderr, "failed to create SHM ring buffer\n");
			return 0;
		}

		// map
		void* SHMMap = mmap(NULL, SHMRingSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (SHMMap == MAP_FAILED)
		{
			fprintf(stderr, "failed to mmap shm ring buffer\n");
			return 0;
		}

		SHMRingHeader	= (FMADSHMRingHeader_t*)SHMMap;
		fprintf(stderr, "SHMRing Version :%08x ChunkSize:%i\n", SHMRingHeader->Version, SHMRingHeader->ChunkSize);
		assert(SHMRingHeader->Version == OUTPUT_VERSION_1_00);

		// reset get heade
		assert(sizeof(FMADSHMRingHeader_t) == 8*16*2);
		SHMRingData	= (u8*)(SHMRingHeader + 1);

		fprintf(stderr, "SHM Initial State Put:%08x Get:%08x\n", SHMRingHeader->Get, SHMRingHeader->Put);
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
	for (int i=0; i < g_CPUWorkerCnt; i++)
	{
		pthread_create(&s_PktBlockThread[i], NULL, PktBlock_Worker, (void*)NULL); 
		CPUCnt++;
	}

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

	u64 StartTS					= clock_ns();

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

		if (IsFMADRING)
		{
			fProfile_Start(5, "PacketFetch_Ring");

			// wait foe new data
			bool IsExit = false;
			do
			{
				// update consumer HB
				SHMRingHeader->HBGetTSC = rdtsc();

				// check producer is alive still & producer did not
				// exit due to end of stream
				s64 dTSC = rdtsc() - SHMRingHeader->HBPutTSC;
				if ((dTSC > 60e9) && (SHMRingHeader->End == -1))
				{
					fprintf(stderr, "producer timeout: %lli\n", dTSC);
					IsExit = true;
					break;
				}

				// there is data
				if (SHMRingHeader->Get != SHMRingHeader->Put) break;

				// check for end of stream
				if (SHMRingHeader->End == SHMRingHeader->Get)
				{
					fprintf(stderr, "end of capture End:%08x Put:%08x Get:%08x\n", SHMRingHeader->End, SHMRingHeader->Put, SHMRingHeader->Get);
					IsExit = true;
					break;
				}

				// wait a bit for a block to become ready
				//usleep(0);
				ndelay(250);

			} while (SHMRingHeader->Get == SHMRingHeader->Put);

			fProfile_Stop(5);

			if (IsExit) break;

			// get the chunk header info
			u32 Index 	= SHMRingHeader->Get & SHMRingHeader->Mask;	
			FMADHeader_t* Header = (FMADHeader_t*)(SHMRingData + Index * SHMRingHeader->ChunkSize);

			PktBlock->PktCnt		= Header->PktCnt; 
			PktBlock->ByteWire		= Header->BytesWire;
			PktBlock->ByteCapture	= Header->BytesCapture;
			PktBlock->TSFirst		= Header->TSStart;
			PktBlock->TSLast		= Header->TSEnd;
			PktBlock->BufferLength	= Header->Length;

			// copy to local buffer
			assert(Header->Length < PktBlock->BufferMax);
			memcpy(PktBlock->Buffer, Header + 1, Header->Length);

			// copy stream cat stats
			StreamCAT_BytePending = Header->BytePending;
			StreamCAT_CPUActive   = Header->CPUActive / (float)0x10000;
			StreamCAT_CPUFetch    = Header->CPUFetch / (float)0x10000;
			StreamCAT_CPUSend     = Header->CPUSend / (float)0x10000;

			// signal its been consued to stream_cat
			SHMRingHeader->Get++;

			fProfile_Stop(5);
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
			PktBlock->OutputTS 	= NextOutputTS - g_OutputTimeNS;			// timestamp is the START period 
																			// of the snapshot. 
																			//e.g. tiemstamp 09:00:00 contains packets betwen 09:00:00 -> 09:00:00.99999999999

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

		// reset the JSON Output block 
		s_JSONLine = s_JSONBuffer;

		// aggreate pipeline stats
		fProfile_Start(1, "Aggregate");
		bool IsFlush = false;
		for (int i=0; i < s_PipelinePos; i++)
		{
			IsFlush |= Pipeline_StatsAggregate(s_PipelineList[i]);
		}
		fProfile_Stop(1);

		// if JSON buffer was written to then kick it
		fProfile_Start(6, "OutputJSON");
		if (IsFlush)
		{
			u32 Length = s_JSONLine - s_JSONBuffer;
			Output_BufferAdd(s_Output, s_JSONBuffer, Length, 1);
		}
		fProfile_Stop(6);

		// write processing status 
		u64 TSC = rdtsc();
		if (TSC > NextPrintTSC)
		{
			NextPrintTSC = TSC + 3e9; 

			u8 TimeStr[1024];
			clock_date_t c	= ns2clock(LastTS);
			sprintf(TimeStr, "%04i-%02i-%02i %02i:%02i:%02i", c.year, c.month, c.day, c.hour, c.min, c.sec);


			static u64 LastTS 			= 0;
			static u64 LastPCAPOffset 	= 0;
			static u64 LastPktUnique 	= 0;

			u64 TS 				= clock_ns();
			double dT			= (TS - LastTS)/1e9;

			double Bps 		= ((PCAPOffset - LastPCAPOffset)* 8.0) / dT; 
			double Pps 		= (TotalPktUnique - LastPktUnique) / dT; 

			LastTS 			= TS;
			LastPCAPOffset 	= PCAPOffset;
			LastPktUnique	= TotalPktUnique;

			u32 QueueDepth = s_PipelineList[0]->QueueDepth;

			// ES push stats
			float OutputWorkerCPU 		= 0;
			float OutputWorkerCPURecv 	= 0;
			u64 OutputPendingB 			= 0;
			u64 OutputPushSizeB 		= 0;
			u64 OutputPushBps 			= 0;
			Output_Stats(s_Output, true,  &OutputWorkerCPU, NULL, NULL, &OutputWorkerCPURecv, NULL, &OutputPendingB, &OutputPushSizeB, &OutputPushBps);

			// aggregat stats
			u64 WorkerTotal	 	= 0;
			u64 WorkerUsed 		= 0;
			u64 WorkerAlloc 	= 0;
			for (int i=0; i < g_CPUWorkerCnt; i++)
			{
				WorkerTotal	 	+= s_PipeWorkerCPUTotal[i]; 
				WorkerUsed 		+= s_PipeWorkerCPU[i]; 
				WorkerAlloc 	+= s_PipeWorkerCPUAlloc[i]; 

				s_PipeWorkerCPUReset[i]	= true;
			}

			float WorkerCPU = WorkerUsed * inverse(WorkerTotal);
			fprintf(stderr, "[%.3f H][%s] : Total Bytes %.3f GB Pipelines %4i Speed: %.3fGbps %.3f Mpps StreamCat: %6.2f MB Fetch %.2f Send %.2f : P0 QueueDepth:%i PipeCPU:%.3f %.3f | ESPush:%6lli ESErr %4lli | OutCPU:%.2f OutPush: %.2f MB OutQueue:%6.1fMB %.3f Gbps\n", 
						(TS - StartTS) / (60*60*1e9), 
						TimeStr, 
						PCAPOffset / 1e9, 
						s_PipelinePos,
						Bps / 1e9, 
						Pps / 1e6, 
						StreamCAT_BytePending / (float)kMB(1), 
						StreamCAT_CPUFetch,
						StreamCAT_CPUSend,
						
						QueueDepth,
						WorkerCPU,
						(float)WorkerAlloc / (float)WorkerTotal,

						Output_ESPushCnt(s_Output),
						Output_ESErrorCnt(s_Output),
						OutputWorkerCPU,

						
						OutputPushSizeB / (float)kMB(1),
						OutputPendingB / (float)kMB(1) ,
						(float)(OutputPushBps / 1e9)
			);
			fflush(stderr);
			fflush(stdout);

			static int cnt = 0;
			if (cnt++ > 10)
			{
				fProfile_Stop(0);

				cnt = 0;
				fProfile_Dump(0);
			}
		}
		fProfile_Stop(0);
	}

	// inert an EOS block 
	u32 SeqNoFinal = SeqNo;
	fprintf(stderr, "Final Seqno:%i : StatsFree:%p NextOutputTS:%lli\n", SeqNoFinal, s_PipeStatsFree, NextOutputTS);
	{

		PacketBlock_t* PktBlock = PktBlock_Allocate();
		assert(PktBlock != NULL);

		PktBlock->SeqNo			= SeqNo++;
		PktBlock->PktCnt		= 0;
		PktBlock->ByteWire		= 0;
		PktBlock->ByteCapture	= 0;

		PktBlock->TSFirst 		= NextOutputTS;
		PktBlock->TSLast 		= NextOutputTS;

		PktBlock->IsOutput		= false;
		PktBlock->OutputTS 		= NextOutputTS;

		// push to processing queue
		s_PacketBlockRing[ s_PacketBlockPut & s_PacketBlockMsk ] = PktBlock;
		s_PacketBlockPut++;
	}
	fprintf(stderr, "LastTS: %s %lli\n", FormatTS(LastTS), LastTS );

	// wait for all blocks have completed
	fprintf(stderr, "Wait for Blocks to finish Get:%08x Put:%08x\n", s_PacketBlockGet, s_PacketBlockPut);
	while (s_PacketBlockGet != s_PacketBlockPut)
	{
		/*
		// keep aggregating to free up stats blocks
		//
		// 2019/12/10 can not do this as it may process
		//            final chunks without flushing to JSON
		//            have increased the total allocated stats
		//            wich should resolve the previous out of stats problem
		for (int i=0; i < s_PipelinePos; i++)
		{
			Pipeline_StatsAggregate(s_PipelineList[i]);
		}
		*/
		usleep(10e3);
	}

	// signal threads to exit and wait 
	fprintf(stderr, "Request Exit\n");
	g_Exit = true;
	for (int i=0; i < CPUCnt; i++)
	{
		pthread_join(s_PktBlockThread[i], 0);
		fprintf(stderr, "  BPF Worker thread join %i\n", i); 
	}

	// reset the JSON Output block 
	s_JSONLine = s_JSONBuffer;

	// aggreate after final processing 
	fprintf(stderr, "Final Aggregation\n");
	for (int i=0; i < s_PipelinePos; i++)
	{
		// find the final stats for the pipline
		Pipeline_t* P = s_PipelineList[i];
		for (int cpu=0; cpu < g_CPUActive; cpu++)
		{
			PipelineStats_t* Stats = P->QueueTail[cpu];
			if (!Stats)
			{
				fprintf(stderr, "pipe:%4i cpu:%i null %p %p\n", i, cpu, P->QueueHead[cpu], P->QueueTail[cpu]);
				continue;
			}

			//fprintf(stderr, "pipe:%4i cpu:%i Found Final SeqNo:%i IsFlush:%i Final:%i LastTS:%lli\n", i, cpu, Stats->SeqNo, Stats->IsFlush, Stats->SeqNo == SeqNoFinal, Stats->LastTS);

			// if it the final seq number?
			if (Stats->SeqNo == SeqNoFinal)
			{
				// force the pipes last stats time 
				// to be the next output snapshot timestamp 
				Stats->LastTS 	= NextOutputTS; 
				Stats->OutputTS	= NextOutputTS - g_OutputTimeNS; 

				// force output flush
				Stats->IsFlush = true;
			}
		}
		// aggregate stats from all CPUs 
		Pipeline_StatsAggregate(P);
	}
	fprintf(stderr, "Wite Final JSON\n");

	// generate the final JSON output 
	u32 Length = s_JSONLine - s_JSONBuffer;
	Output_BufferAdd(s_Output, s_JSONBuffer, Length, 1);

	// flush pipe with last log
	fprintf(stderr, "Pipeline Close\n");
	for (int p=0; p < s_PipelinePos; p++)
	{
		Pipeline_t* Pipe = s_PipelineList[p];
		Pipeline_Close(Pipe, LastTS);
	}

	// wait for final kick to finish
	usleep(100e3);
	fprintf(stderr, "Output Close\n");
	Output_Close(s_Output);

	//printf("Final JSON %i\n%s\n", Length, s_JSONBuffer);

	printf("TotalPktUnique : %10lli\n", TotalPktUnique);
	printf("TotalPkt       : %10lli\n", TotalPkt);
	printf("TotalPktHit    : %10lli\n", TotalPktHit);

	float dT = (clock_ns() - StartTS);
	printf("Total Time     : %.f Sec\n", dT/1e9);

	float bps = (PCAPOffset * 8.0) / (dT / 1e9);
	float pps = TotalPktUnique / (dT / 1e9);

	u8 TimeStr[128];
	clock_str(TimeStr, clock_date() );
	printf("%s Performance : %.3f sec  %.2f GB %.3f Gbps %.3fMpps\n", TimeStr, dT/1e9, PCAPOffset / 1e9, bps / 1e9, pps/1e6);

	return 0;
}
