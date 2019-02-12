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
	u32*			BinPkt;						// histograms for packets that hit the BPF filter
	u32*			BinByte;

	u64				Pkt;						// number of pkts/bytes added in this time slot
	u64				Byte;

	u64				AllPkt;						// total packets checked (inc BPF miss) 
	u64				AllByte;					// used to calcuate raio of this BPF flow
													// to all of the traffic

	u32				RMON1[RMON1_MAX];			// time RMON stats

} PipelineTime_t;

typedef struct
{
	// rule definition 
	u8				Name[256];						// string name of the expression

	// output files
	u8				OutputFileName[1024];			// full path of output name
	FILE*			OutputFile;						// file handle to write
	u64				OutputNS;						// nanos between outputs 

	bool			BPFValid;						// BPF expression compiled sucessfully
	u8				BPF[1024];
	u8				BPFCode[16*1024];

	u64				LastTS;							// TS of last packet hit

	u64				TotalPkt;						// total packets hit
	u64				TotalByte;						// total bytes hit 

	u64				TCPCnt_FIN;						// total tcp FIN pkts 
	u64				TCPCnt_SYN;						// total tcp SYN pkts 
	u64				TCPCnt_RST;						// total tcp RST pkts 
	u64				TCPCnt_ACK;						// total tcp ACK pkts 
	u64				TCPCnt_PSH;						// total tcp PSH pkts 

	// these fields get cleared every log cycle

	u32				TimeBinMax;						// max bins
	u64				TimeBinNS;						// time bin in nanos	
	PipelineTime_t	Time;

} Pipeline_t;

typedef struct PacketBuffer_t
{
	u32						PktCnt;				// number of packets in this buffer
	u32						ByteWire;			// total wire bytes 
	u32						ByteCapture;		// total captured bytes 

	u64						TSFirst;			// first Pkt TS
	u64						TSLast;				// last Pkt TS

	u32						BufferMax;			// max size
	u8*						Buffer;				// memory buffer
	u32						BufferLength;		// length of valid data in buffer

} PacketBuffer_t;



extern u64				g_OutputTimeNS;				// time between outputs

static u32				s_PipelinePos = 0;
static u32				s_PipelineMax = 16*1024;
static Pipeline_t* 		s_PipelineList[16*1024];	

//-------------------------------------------------------------------------------------------------
static inline u32 Length2RMON1(const u32 Length)
{
	if (Length < 64) return RMON1_RUNT;
	if (Length == 64) return RMON1_64;
	if (Length <= 127) return RMON1_64_127;
	if (Length <= 255) return RMON1_128_255;
	if (Length <= 511) return RMON1_256_511;
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

	u32 Index 				= s_PipelinePos++;	
	s_PipelineList[Index]	= Pipe;

	const u8* Name = lua_tostring(L, -1);	
	strncpy(Pipe->Name, Name, sizeof(Pipe->Name) );

	printf("[%-40s] create a pipeline\n", Pipe->Name);

	// default bandwidth stats
	Pipe->TimeBinNS			= 1e6;
	Pipe->OutputNS			= g_OutputTimeNS;
	Pipe->TimeBinMax		= Pipe->OutputNS / Pipe->TimeBinNS;

	Pipe->Time.BinPkt		= (u32*)malloc( sizeof(u32) * Pipe->TimeBinMax);
	Pipe->Time.BinByte		= (u32*)malloc( sizeof(u32) * Pipe->TimeBinMax);

	memset(Pipe->Time.BinPkt,  0, sizeof(u32) * Pipe->TimeBinMax);
	memset(Pipe->Time.BinByte, 0, sizeof(u32) * Pipe->TimeBinMax);

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

	Pipe->TimeBinNS 	= TimeBucketNS;
	Pipe->TimeBinMax	= Pipe->OutputNS / Pipe->TimeBinNS;

	if (Pipe->TimeBinMax > TIME_BIN_MAX)
	{
		printf("[%-40s] ERROR: set TimeBucket %lli nsec too small for current config (%i/%i)\n", Pipe->Name, Pipe->TimeBinNS, Pipe->TimeBinMax, TIME_BIN_MAX);
		lua_pushnumber(L, 1);
		return 1;
	}

	// reallocate bins
	free(Pipe->Time.BinPkt);
	free(Pipe->Time.BinByte);

	Pipe->Time.BinPkt		= (u32*)malloc( sizeof(u32) * Pipe->TimeBinMax);
	Pipe->Time.BinByte		= (u32*)malloc( sizeof(u32) * Pipe->TimeBinMax);

	assert(Pipe->Time.BinPkt != NULL);
	assert(Pipe->Time.BinByte != NULL);

	memset(Pipe->Time.BinPkt,  0, sizeof(u32) * Pipe->TimeBinMax);
	memset(Pipe->Time.BinByte, 0, sizeof(u32) * Pipe->TimeBinMax);

	// new microburst time bin set 
	printf("[%-40s] set TimeBucket %lli nsec\n", Pipe->Name, Pipe->TimeBinNS);

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
	Pipe->OutputFile = fopen(Pipe->OutputFileName, "w+");
	if (!Pipe->OutputFile)
	{
		printf("[%-40s] ERROR: failed to create output filename (%s)\n", Pipe->OutputFileName);

		lua_pushnumber(L, 1);
		return 1;
	}
	printf("[%-40s] created output filename (%s)\n", Pipe->Name, Pipe->OutputFileName);

	fprintf(Pipe->OutputFile, "BPF Expression: (%s)\n", Pipe->BPF);
	fprintf(Pipe->OutputFile, "Burst Bucket  : %16lli nsec\n", Pipe->TimeBinNS);
	fprintf(Pipe->OutputFile, "Output Time   : %16lli nsec\n", Pipe->OutputNS);
	fprintf(Pipe->OutputFile, "------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");

	fprintf(Pipe->OutputFile, "%32s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s, %20s\n",
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
		if (BytesMax < Pipe->Time.BinByte[i]) 
		{
			BytesMax = Pipe->Time.BinByte[i]; 
		}

		if (PktMax < Pipe->Time.BinPkt[i]) 
		{
			PktMax = Pipe->Time.BinPkt[i]; 
		}

		// calcualte mean / stdev 
		ByteS0	+= 1; 
		ByteS1 	+= Pipe->Time.BinByte[i];
		ByteS2 	+= Pipe->Time.BinByte[i] * Pipe->Time.BinByte[i];

		PktS0	+= 1; 
		PktS1 	+= Pipe->Time.BinPkt[i];
		PktS2 	+= Pipe->Time.BinPkt[i] * Pipe->Time.BinPkt[i];
	}

	u64 BpsMax  =  1e9 * (8.0 * (float)BytesMax) / (float)Pipe->TimeBinNS;
	u64 BpsMean = (1e9 * 8.0 * ByteS1) / g_OutputTimeNS; 

	u64 PpsMax  =  1e9 * ((float)PktMax) / (float)Pipe->TimeBinNS;
	u64 PpsMean = (1e9 * PktS1) / g_OutputTimeNS; 

	float BytePct = Pipe->Time.Byte * inverse(Pipe->Time.AllByte); 

	u8 DateTime[128];
	ns2str(DateTime, LastTS);

	fprintf(Pipe->OutputFile, "%32s, %20lli, %20lli, %20lli, %20.3f, %20.3f, %20.6f, %20lli, %20lli, %20i, %20i, %20i, %20i, %20i, %20i, %20i, %20i, %20i, %20i, %20i, %20i, %20i, %20i, %20i, %20i\n",
			DateTime,	
			LastTS,
			Pipe->TotalPkt,
			Pipe->TotalByte,
			BpsMax/1e6,	
			BpsMean/1e6,
			BytePct,

			PpsMax,	
			PpsMean,
		
			Pipe->Time.RMON1[RMON1_RUNT],
			Pipe->Time.RMON1[RMON1_64],
			Pipe->Time.RMON1[RMON1_64_127],
			Pipe->Time.RMON1[RMON1_128_255],
			Pipe->Time.RMON1[RMON1_256_511],
			Pipe->Time.RMON1[RMON1_512_1023],
			Pipe->Time.RMON1[RMON1_1024_1518],
			Pipe->Time.RMON1[RMON1_1024_1518] + Pipe->Time.RMON1[RMON1_1519_2047],
			Pipe->Time.RMON1[RMON1_2048_4095],
			Pipe->Time.RMON1[RMON1_4096_8191],
			Pipe->Time.RMON1[RMON1_8192],

			Pipe->TCPCnt_FIN,
			Pipe->TCPCnt_SYN,
			Pipe->TCPCnt_RST,
			Pipe->TCPCnt_ACK,
			Pipe->TCPCnt_PSH
	);

	fflush(Pipe->OutputFile);

	// reset the time buckets
	memset(Pipe->Time.BinPkt, 0, sizeof(u32) * Pipe->TimeBinMax );
	memset(Pipe->Time.BinByte, 0, sizeof(u32) * Pipe->TimeBinMax );
	Pipe->Time.Pkt = 0;
	Pipe->Time.Byte = 0;
	Pipe->Time.AllPkt = 0;
	Pipe->Time.AllByte = 0;
	memset(&Pipe->Time.RMON1, 0, sizeof(Pipe->Time.RMON1) );

	// clear tcp flag stats 
	Pipe->TCPCnt_FIN = 0;
	Pipe->TCPCnt_SYN = 0;
	Pipe->TCPCnt_RST = 0;
	Pipe->TCPCnt_ACK = 0;
	Pipe->TCPCnt_PSH = 0;
}

//-------------------------------------------------------------------------------------------------
// close 
void Pipeline_Close(Pipeline_t* Pipe, u64 LastTS)
{
	// flush last log entry
	Pipeline_WriteLog(Pipe, LastTS);

	fclose(Pipe->OutputFile);
	Pipe->OutputFile = NULL;
}

//-------------------------------------------------------------------------------------------------

int Parse_Start(void)
{
	u64 StartTS					= clock_ns();
	u64 PCAPOffset				= 0;
	u64 TotalPkt				= 0;

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

	// create packet buffer
	PacketBuffer_t*	PktBlock	= (PacketBuffer_t*)malloc(sizeof(PacketBuffer_t));
	memset(PktBlock, 0, sizeof(PacketBuffer_t));

	PktBlock->BufferMax			= kKB(256);
	PktBlock->Buffer			= malloc( PktBlock->BufferMax ); 
	assert(PktBlock->Buffer != 0);

	u64   StreamCAT_BytePending	= 0;
	float StreamCAT_CPUActive	= 0;
	float StreamCAT_CPUFetch	= 0;
	float StreamCAT_CPUSend		= 0;

	while (!feof(FIn))
	{
		// reset packet buffer
		PktBlock->PktCnt		= 0;
		PktBlock->ByteWire		= 0;
		PktBlock->ByteCapture	= 0;

		PktBlock->TSFirst		= -1;
		PktBlock->TSLast		= 0;

		PktBlock->BufferLength	= 0;

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

		// process a block
		u32 Offset = 0;
		for (int i=0; i < PktBlock->PktCnt; i++)
		{
			FMADPacket_t* Pkt = (FMADPacket_t*)(PktBlock->Buffer + Offset);	
			Offset 			+= sizeof(FMADPacket_t);
			Offset 			+= Pkt->LengthCapture; 

			// pcap header for BPF parser
			struct pcap_pkthdr hdr;
			hdr.ts.tv_sec	= Pkt->TS / (u64)1e9;
			hdr.ts.tv_usec	= Pkt->TS % (u64)1e9;
			hdr.caplen		= Pkt->LengthCapture; 
			hdr.len			= Pkt->LengthWire;

			u8* PacketPayload	= (u8*)(Pkt + 1);

			// process all pipelines	
			for (int p=0; p < s_PipelinePos; p++)
			{
				Pipeline_t* Pipe = s_PipelineList[p];

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

				// run BPF expression
				int Result = pcap_offline_filter((struct bpf_program*)Pipe->BPFCode, &hdr, (const u8*)PacketPayload);
				if (Result != 0)
				{
					// BPF got a hit
					Pipe->TotalPkt	+= 1;
					Pipe->TotalByte	+= Pkt->LengthWire;

					Pipe->LastTS = Pkt->TS;

					// update Bins
					Pipe->Time.BinPkt [TimeIndex] += 1;
					Pipe->Time.BinByte[TimeIndex] += Pkt->LengthWire;

					// total stats
					Pipe->Time.Pkt	+= 1;
					Pipe->Time.Byte	+= Pkt->LengthWire;

					// update RMON stats
					u32 RMONIndex = Length2RMON1(Pkt->LengthWire);
					Pipe->Time.RMON1[RMONIndex]++;

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

									Pipe->TCPCnt_FIN  += TCP_FLAG_FIN(TCP->Flags);
									Pipe->TCPCnt_SYN  += TCP_FLAG_SYN(TCP->Flags);
									Pipe->TCPCnt_RST  += TCP_FLAG_RST(TCP->Flags);
									Pipe->TCPCnt_ACK  += TCP_FLAG_ACK(TCP->Flags);
									Pipe->TCPCnt_PSH  += TCP_FLAG_PSH(TCP->Flags);
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
				}

				// time bin in comparsion 
				Pipe->Time.AllPkt 	+= 1;
				Pipe->Time.AllByte	+= Pkt->LengthWire;
			}

			// update stats
			PCAPOffset 	+= sizeof(FMADPacket_t);
			PCAPOffset 	+= Pkt->LengthCapture; 
			TotalPkt	+= 1;

			// write the per filter log files
			LastTS 		= Pkt->TS;
			if (LastTS > NextOutputTS)
			{
				// print every 60sec
				NextOutputTS = LastTS + g_OutputTimeNS;
		
				// process all pipelines
				for (int p=0; p < s_PipelinePos; p++)
				{
					Pipeline_t* Pipe = s_PipelineList[p];
					Pipeline_WriteLog(Pipe, LastTS);
				}
			}
		}

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
			fprintf(stderr, "[%.3f H][%s] : Total Bytes %.3f GB Speed: %.3fGbps StreamCat: %6.2f MB Fetch %.2f Send %.2f\n", 
						dT / (60*60), 
						TimeStr, 
						PCAPOffset / 1e9, 
						Bps / 1e9, 
						StreamCAT_BytePending / (float)kMB(1), 
						StreamCAT_CPUFetch,
						StreamCAT_CPUSend);
		}
	}

	// flush pipe with last log
	for (int p=0; p < s_PipelinePos; p++)
	{
		Pipeline_t* Pipe = s_PipelineList[p];
		Pipeline_Close(Pipe, LastTS);
	}

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
