#pragma once

#include "forward.hpp"

#include <cinttypes>
#include <type_traits>

namespace clepta
{
	template <typename T>
	struct unicode_string_t
	{
		uint16_t Length;
		uint16_t MaximumLength;

		T Buffer;
	};

	template <typename T>
	struct list_entry_t
	{
		T Flink;
		T Blink;
	};

	template <typename T>
	struct peb_ldr_data_t
	{
		uint32_t Length;
		uint8_t Initialized;
		T SsHandle;
		list_entry_t<T> InLoadOrderModuleList; // Module list in order of load
		list_entry_t<T> InMemoryOrderModuleList; // Module list in order of memory
		list_entry_t<T> InInitializationOrderModuleList; // Module list in order of initialization
		T EntryInProgress;
		uint8_t ShutdownInProgress;
		T ShutdownThreadId;
	};

	template <typename T>
	struct ldr_data_table_entry_base_t
	{
		list_entry_t<T> InLoadOrderLinks;
		list_entry_t<T> InMemoryOrderLinks;
		list_entry_t<T> InInitializationOrderLinks;
		T DllBase;
		T EntryPoint;
		uint32_t SizeOfImage;
		unicode_string_t<T> FullDllName;
		unicode_string_t<T> BaseDllName;
		uint32_t Flags;
		uint16_t LoadCount;
		uint16_t TlsIndex;
		list_entry_t<T> HashLinks;
		uint32_t TimeDateStamp;
		T EntryPointActivationContext;
		T PatchInformation;
	};

	template <typename T = uint64_t>
	struct peb_t
	{
		static_assert(std::is_same_v<T, uint32_t> || std::is_same_v<T, uint64_t>, "T must be uint32_t or uint64_t");
		uint8_t InheritedAddressSpace;
		uint8_t ReadImageFileExecOptions;
		uint8_t BeingDebugged;
		union
		{
			uint8_t BitField;
			struct
			{
				uint8_t ImageUsesLargePages : 1;
				uint8_t IsProtectedProcess : 1;
				uint8_t IsImageDynamicallyRelocated : 1;
				uint8_t SkipPatchingUser32Forwarders : 1;
				uint8_t IsPackagedProcess : 1;
				uint8_t IsAppContainer : 1;
				uint8_t IsProtectedProcessLight : 1;
				uint8_t SpareBits : 1;
			};
		};
		T Mutant;
		T ImageBaseAddress;
		T Ldr;
		T ProcessParameters;
		T SubSystemData;
		T ProcessHeap;
		T FastPebLock;
		T AtlThunkSListPtr;
		T IFEOKey;
		union
		{
			T CrossProcessFlags;
			struct
			{
				uint32_t ProcessInJob : 1;
				uint32_t ProcessInitializing : 1;
				uint32_t ProcessUsingVEH : 1;
				uint32_t ProcessUsingVCH : 1;
				uint32_t ProcessUsingFTH : 1;
				uint32_t ReservedBits0 : 27;
			};
		};
		union
		{
			T KernelCallbackTable;
			T UserSharedInfoPtr;
		};
		uint32_t SystemReserved;
		uint32_t AtlThunkSListPtr32;
		T ApiSetMap;
		union
		{
			uint32_t TlsExpansionCounter;
			T Padding2;
		};
		T TlsBitmap;
		uint32_t TlsBitmapBits[2];
		T ReadOnlySharedMemoryBase;
		T SparePvoid0;
		T ReadOnlyStaticServerData;
		T AnsiCodePageData;
		T OemCodePageData;
		T UnicodeCaseTableData;
		uint32_t NumberOfProcessors;
		uint32_t NtGlobalFlag;
		LARGE_INTEGER CriticalSectionTimeout;
		T HeapSegmentReserve;
		T HeapSegmentCommit;
		T HeapDeCommitTotalFreeThreshold;
		T HeapDeCommitFreeBlockThreshold;
		uint32_t NumberOfHeaps;
		uint32_t MaximumNumberOfHeaps;
		T ProcessHeaps;
		T GdiSharedHandleTable;
		T ProcessStarterHelper;
		union
		{
			uint32_t GdiDCAttributeList;
			T Padding3;
		};
		T LoaderLock;
		uint32_t OSMajorVersion;
		uint32_t OSMinorVersion;
		uint16_t OSBuildNumber;
		uint16_t OSCSDVersion;
		uint32_t OSPlatformId;
		uint32_t ImageSubsystem;
		uint32_t ImageSubsystemMajorVersion;
		union
		{
			uint32_t ImageSubsystemMinorVersion;
			T Padding4;
		};
		T ActiveProcessAffinityMask;
		uint32_t GdiHandleBuffer[std::conditional_t<std::is_same_v<T, uint32_t>, std::integral_constant<int32_t, 34>, std::integral_constant<int32_t, 60>>::value];
		T PostProcessInitRoutine;
		T TlsExpansionBitmap;
		uint32_t TlsExpansionBitmapBits[32];
		union
		{
			uint32_t SessionId;
			T Padding5;
		};
		ULARGE_INTEGER AppCompatFlags;
		ULARGE_INTEGER AppCompatFlagsUser;
		T pShimData;
		T AppCompatInfo;
		unicode_string_t<T> CSDVersion;
		T ActivationContextData;
		T ProcessAssemblyStorageMap;
		T SystemDefaultActivationContextData;
		T SystemAssemblyStorageMap;
		T MinimumStackCommit;
		T FlsCallback;
		list_entry_t<T> FlsListHead;
		T FlsBitmap;
		uint32_t FlsBitmapBits[4];
		uint32_t FlsHighIndex;
		T WerRegistrationData;
		T WerShipAssertPtr;
		T pUnused;
		T pImageHeaderHash;
		union
		{
			uint64_t TracingFlags;
			struct
			{
				uint32_t HeapTracingEnabled : 1;
				uint32_t CritSecTracingEnabled : 1;
				uint32_t LibLoaderTracingEnabled : 1;
				uint32_t SpareTracingBits : 29;
			};
		};
		T CsrServerReadOnlySharedMemoryBase;
	};
}