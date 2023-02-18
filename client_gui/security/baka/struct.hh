#pragma once
#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#endif
#include <Windows.h>
#include <winternl.h>

#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <intrin.h>

#define RTL_MAX_DRIVE_LETTERS 32
#define WINDOWS_NUMBER_XP 6
#define WINDOWS_NUMBER_7 7
#define WINDOWS_NUMBER_8 8
#define WINDOWS_NUMBER_8_1 9
#define WINDOWS_NUMBER_10 10
#define WINDOWS_NUMBER_11 11

#define GDI_HANDLE_BUFFER_SIZE32    34
#define GDI_HANDLE_BUFFER_SIZE64    60

#define NtCurrentProcess        ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread         ((HANDLE)(LONG_PTR)-2)
#define NtCurrentPeb()          (NtCurrentTeb()->ProcessEnvironmentBlock)
#define NtCurrentProcessId()    (NtCurrentTeb()->ClientId.UniqueProcess)
#define NtCurrentThreadId()     (NtCurrentTeb()->ClientId.UniqueThread)
#define RtlProcessHeap()        (NtCurrentPeb()->ProcessHeap)


#define OBJ_CASE_INSENSITIVE   0x00000040L

#define 	LDR_IS_DATAFILE(handle)   (((ULONG_PTR)(handle)) & (ULONG_PTR)1)

#define 	LDR_DATAFILE_TO_VIEW(x)   ((PVOID)(((ULONG_PTR)(x)) & ~(ULONG_PTR)1))

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef enum _system_information_class
{
    systembasicinformation, // q: system_basic_information
    systemprocessorinformation, // q: system_processor_information
    systemperformanceinformation, // q: system_performance_information
    systemtimeofdayinformation, // q: system_timeofday_information
    systempathinformation, // not implemented
    systemprocessinformation, // q: system_process_information
    systemcallcountinformation, // q: system_call_count_information
    systemdeviceinformation, // q: system_device_information
    systemprocessorperformanceinformation, // q: system_processor_performance_information
    systemflagsinformation, // q: system_flags_information
    systemcalltimeinformation, // not implemented // system_call_time_information // 10
    systemmoduleinformation, // q: rtl_process_modules
    systemlocksinformation, // q: rtl_process_locks
    systemstacktraceinformation, // q: rtl_process_backtraces
    systempagedpoolinformation, // not implemented
    systemnonpagedpoolinformation, // not implemented
    systemhandleinformation, // q: system_handle_information
    systemobjectinformation, // q: system_objecttype_information mixed with system_object_information
    systempagefileinformation, // q: system_pagefile_information
    systemvdminstemulinformation, // q
    systemvdmbopinformation, // not implemented // 20
    systemfilecacheinformation, // q: system_filecache_information; s (requires seincreasequotaprivilege) (info for workingsettypesystemcache)
    systempooltaginformation, // q: system_pooltag_information
    systeminterruptinformation, // q: system_interrupt_information
    systemdpcbehaviorinformation, // q: system_dpc_behavior_information; s: system_dpc_behavior_information (requires seloaddriverprivilege)
    systemfullmemoryinformation, // not implemented
    systemloadgdidriverinformation, // s (kernel-mode only)
    systemunloadgdidriverinformation, // s (kernel-mode only)
    systemtimeadjustmentinformation, // q: system_query_time_adjust_information; s: system_set_time_adjust_information (requires sesystemtimeprivilege)
    systemsummarymemoryinformation, // not implemented
    systemmirrormemoryinformation, // s (requires license value "kernel-memorymirroringsupported") (requires seshutdownprivilege) // 30
    systemperformancetraceinformation, // q; s: (type depends on event_trace_information_class)
    systemobsolete0, // not implemented
    systemexceptioninformation, // q: system_exception_information
    systemcrashdumpstateinformation, // s (requires sedebugprivilege)
    systemkerneldebuggerinformation, // q: system_kernel_debugger_information
    systemcontextswitchinformation, // q: system_context_switch_information
    systemregistryquotainformation, // q: system_registry_quota_information; s (requires seincreasequotaprivilege)
    systemextendservicetableinformation, // s (requires seloaddriverprivilege) // loads win32k only
    systempriorityseperation, // s (requires setcbprivilege)
    systemverifieradddriverinformation, // s (requires sedebugprivilege) // 40
    systemverifierremovedriverinformation, // s (requires sedebugprivilege)
    systemprocessoridleinformation, // q: system_processor_idle_information
    systemlegacydriverinformation, // q: system_legacy_driver_information
    systemcurrenttimezoneinformation, // q
    systemlookasideinformation, // q: system_lookaside_information
    systemtimeslipnotification, // s (requires sesystemtimeprivilege)
    systemsessioncreate, // not implemented
    systemsessiondetach, // not implemented
    systemsessioninformation, // not implemented
    systemrangestartinformation, // q: system_range_start_information // 50
    systemverifierinformation, // q: system_verifier_information; s (requires sedebugprivilege)
    systemverifierthunkextend, // s (kernel-mode only)
    systemsessionprocessinformation, // q: system_session_process_information
    systemloadgdidriverinsystemspace, // s (kernel-mode only) (same as systemloadgdidriverinformation)
    systemnumaprocessormap, // q
    systemprefetcherinformation, // q: prefetcher_information; s: prefetcher_information // pfsnqueryprefetcherinformation
    systemextendedprocessinformation, // q: system_process_information
    systemrecommendedshareddataalignment, // q
    systemcompluspackage, // q; s
    systemnumaavailablememory, // 60
    systemprocessorpowerinformation, // q: system_processor_power_information
    systememulationbasicinformation, // q
    systememulationprocessorinformation,
    systemextendedhandleinformation, // q: system_handle_information_ex
    systemlostdelayedwriteinformation, // q: ulong
    systembigpoolinformation, // q: system_bigpool_information
    systemsessionpooltaginformation, // q: system_session_pooltag_information
    systemsessionmappedviewinformation, // q: system_session_mapped_view_information
    systemhotpatchinformation, // q; s
    systemobjectsecuritymode, // q // 70
    systemwatchdogtimerhandler, // s (kernel-mode only)
    systemwatchdogtimerinformation, // q (kernel-mode only); s (kernel-mode only)
    systemlogicalprocessorinformation, // q: system_logical_processor_information
    systemwow64sharedinformationobsolete, // not implemented
    systemregisterfirmwaretableinformationhandler, // s (kernel-mode only)
    systemfirmwaretableinformation, // system_firmware_table_information
    systemmoduleinformationex, // q: rtl_process_module_information_ex
    systemverifiertriageinformation, // not implemented
    systemsuperfetchinformation, // q; s: superfetch_information // pfquerysuperfetchinformation
    systemmemorylistinformation, // q: system_memory_list_information; s: system_memory_list_command (requires seprofilesingleprocessprivilege) // 80
    systemfilecacheinformationex, // q: system_filecache_information; s (requires seincreasequotaprivilege) (same as systemfilecacheinformation)
    systemthreadpriorityclientidinformation, // s: system_thread_cid_priority_information (requires seincreasebasepriorityprivilege)
    systemprocessoridlecycletimeinformation, // q: system_processor_idle_cycle_time_information[]
    systemverifiercancellationinformation, // not implemented // name:wow64:whnt32querysystemverifiercancellationinformation
    systemprocessorpowerinformationex, // not implemented
    systemreftraceinformation, // q; s: system_ref_trace_information // obqueryreftraceinformation
    systemspecialpoolinformation, // q; s (requires sedebugprivilege) // mmspecialpooltag, then mmspecialpoolcatchoverruns != 0
    systemprocessidinformation, // q: system_process_id_information
    systemerrorportinformation, // s (requires setcbprivilege)
    systembootenvironmentinformation, // q: system_boot_environment_information // 90
    systemhypervisorinformation, // q; s (kernel-mode only)
    systemverifierinformationex, // q; s: system_verifier_information_ex
    systemtimezoneinformation, // s (requires setimezoneprivilege)
    systemimagefileexecutionoptionsinformation, // s: system_image_file_execution_options_information (requires setcbprivilege)
    systemcoverageinformation, // q; s // name:wow64:whnt32querysystemcoverageinformation; expcovqueryinformation
    systemprefetchpatchinformation, // not implemented
    systemverifierfaultsinformation, // s (requires sedebugprivilege)
    systemsystempartitioninformation, // q: system_system_partition_information
    systemsystemdiskinformation, // q: system_system_disk_information
    systemprocessorperformancedistribution, // q: system_processor_performance_distribution // 100
    systemnumaproximitynodeinformation, // q
    systemdynamictimezoneinformation, // q; s (requires setimezoneprivilege)
    systemcodeintegrityinformation, // q: system_codeintegrity_information // secodeintegrityqueryinformation
    systemprocessormicrocodeupdateinformation, // s
    systemprocessorbrandstring, // q // haliquerysysteminformation -> halpgetprocessorbrandstring, info class 23
    systemvirtualaddressinformation, // q: system_va_list_information[]; s: system_va_list_information[] (requires seincreasequotaprivilege) // mmquerysystemvainformation
    systemlogicalprocessorandgroupinformation, // q: system_logical_processor_information_ex // since win7 // kequerylogicalprocessorrelationship
    systemprocessorcycletimeinformation, // q: system_processor_cycle_time_information[]
    systemstoreinformation, // q; s // smquerystoreinformation
    systemregistryappendstring, // s: system_registry_append_string_parameters // 110
    systemaitsamplingvalue, // s: ulong (requires seprofilesingleprocessprivilege)
    systemvhdbootinformation, // q: system_vhd_boot_information
    systemcpuquotainformation, // q; s // psquerycpuquotainformation
    systemnativebasicinformation, // not implemented
    systemspare1, // not implemented
    systemlowpriorityioinformation, // q: system_low_priority_io_information
    systemtpmbootentropyinformation, // q: tpm_boot_entropy_nt_result // exquerytpmbootentropyinformation
    systemverifiercountersinformation, // q: system_verifier_counters_information
    systempagedpoolinformationex, // q: system_filecache_information; s (requires seincreasequotaprivilege) (info for workingsettypepagedpool)
    systemsystemptesinformationex, // q: system_filecache_information; s (requires seincreasequotaprivilege) (info for workingsettypesystemptes) // 120
    systemnodedistanceinformation, // q
    systemacpiauditinformation, // q: system_acpi_audit_information // haliquerysysteminformation -> halpauditqueryresults, info class 26
    systembasicperformanceinformation, // q: system_basic_performance_information // name:wow64:whntquerysysteminformation_systembasicperformanceinformation
    systemqueryperformancecounterinformation, // q: system_query_performance_counter_information // since win7 sp1
    systemsessionbigpoolinformation, // q: system_session_pooltag_information // since win8
    systembootgraphicsinformation, // q; s: system_boot_graphics_information (kernel-mode only)
    systemscrubphysicalmemoryinformation, // q; s: memory_scrub_information
    systembadpageinformation,
    systemprocessorprofilecontrolarea, // q; s: system_processor_profile_control_area
    systemcombinephysicalmemoryinformation, // s: memory_combine_information, memory_combine_information_ex, memory_combine_information_ex2 // 130
    systementropyinterrupttimingcallback,
    systemconsoleinformation, // q: system_console_information
    systemplatformbinaryinformation, // q: system_platform_binary_information
    systemthrottlenotificationinformation,
    systemhypervisorprocessorcountinformation, // q: system_hypervisor_processor_count_information
    systemdevicedatainformation, // q: system_device_data_information
    systemdevicedataenumerationinformation,
    systemmemorytopologyinformation, // q: system_memory_topology_information
    systemmemorychannelinformation, // q: system_memory_channel_information
    systembootlogoinformation, // q: system_boot_logo_information // 140
    systemprocessorperformanceinformationex, // q: system_processor_performance_information_ex // since winblue
    systemspare0,
    systemsecurebootpolicyinformation, // q: system_secureboot_policy_information
    systempagefileinformationex, // q: system_pagefile_information_ex
    systemsecurebootinformation, // q: system_secureboot_information
    systementropyinterrupttimingrawinformation,
    systemportableworkspaceefilauncherinformation, // q: system_portable_workspace_efi_launcher_information
    systemfullprocessinformation, // q: system_process_information with system_process_information_extension (requires admin)
    systemkerneldebuggerinformationex, // q: system_kernel_debugger_information_ex
    systembootmetadatainformation, // 150
    systemsoftrebootinformation,
    systemelamcertificateinformation, // s: system_elam_certificate_information
    systemofflinedumpconfiginformation,
    systemprocessorfeaturesinformation, // q: system_processor_features_information
    systemregistryreconciliationinformation,
    systemedidinformation,
    systemmanufacturinginformation, // q: system_manufacturing_information // since threshold
    systemenergyestimationconfiginformation, // q: system_energy_estimation_config_information
    systemhypervisordetailinformation, // q: system_hypervisor_detail_information
    systemprocessorcyclestatsinformation, // q: system_processor_cycle_stats_information // 160
    systemvmgenerationcountinformation,
    systemtrustedplatformmoduleinformation, // q: system_tpm_information
    systemkerneldebuggerflags,
    systemcodeintegritypolicyinformation, // q: system_codeintegritypolicy_information
    systemisolatedusermodeinformation, // q: system_isolated_user_mode_information
    systemhardwaresecuritytestinterfaceresultsinformation,
    systemsinglemoduleinformation, // q: system_single_module_information
    systemallowedcpusetsinformation,
    systemdmaprotectioninformation, // q: system_dma_protection_information
    systeminterruptcpusetsinformation, // q: system_interrupt_cpu_set_information // 170
    systemsecurebootpolicyfullinformation, // q: system_secureboot_policy_full_information
    systemcodeintegritypolicyfullinformation,
    systemaffinitizedinterruptprocessorinformation,
    systemrootsiloinformation, // q: system_root_silo_information
    systemcpusetinformation, // q: system_cpu_set_information // since threshold2
    systemcpusettaginformation, // q: system_cpu_set_tag_information
    systemwin32werstartcallout,
    systemsecurekernelprofileinformation, // q: system_secure_kernel_hyperguard_profile_information
    systemcodeintegrityplatformmanifestinformation, // q: system_secureboot_platform_manifest_information // since redstone
    systeminterruptsteeringinformation, // 180
    systemsupportedprocessorarchitectures,
    systemmemoryusageinformation, // q: system_memory_usage_information
    systemcodeintegritycertificateinformation, // q: system_codeintegrity_certificate_information
    systemphysicalmemoryinformation, // q: system_physical_memory_information // since redstone2
    systemcontrolflowtransition,
    systemkerneldebuggingallowed,
    systemactivitymoderationexestate, // system_activity_moderation_exe_state
    systemactivitymoderationusersettings, // system_activity_moderation_user_settings
    systemcodeintegritypoliciesfullinformation,
    systemcodeintegrityunlockinformation, // system_codeintegrity_unlock_information // 190
    systemintegrityquotainformation,
    systemflushinformation, // q: system_flush_information
    maxsysteminfoclass
} system_information_class;

typedef enum _processinfoclass
{
    processbasicinformation, // q: process_basic_information, process_extended_basic_information
    processquotalimits, // qs: quota_limits, quota_limits_ex
    processiocounters, // q: io_counters
    processvmcounters, // q: vm_counters, vm_counters_ex, vm_counters_ex2
    processtimes, // q: kernel_user_times
    processbasepriority, // s: kpriority
    processraisepriority, // s: ulong
    processdebugport, // q: handle
    processexceptionport, // s: handle
    processaccesstoken, // s: process_access_token
    processldtinformation, // qs: process_ldt_information // 10
    processldtsize, // s: process_ldt_size
    processdefaultharderrormode, // qs: ulong
    processioporthandlers, // (kernel-mode only)
    processpooledusageandlimits, // q: pooled_usage_and_limits
    processworkingsetwatch, // q: process_ws_watch_information[]; s: void
    processusermodeiopl,
    processenablealignmentfaultfixup, // s: boolean
    processpriorityclass, // qs: process_priority_class
    processwx86information,
    processhandlecount, // q: ulong, process_handle_information // 20
    processaffinitymask, // s: kaffinity
    processpriorityboost, // qs: ulong
    processdevicemap, // qs: process_devicemap_information, process_devicemap_information_ex
    processsessioninformation, // q: process_session_information
    processforegroundinformation, // s: process_foreground_background
    processwow64information, // q: ulong_ptr
    processimagefilename, // q: unicode_string
    processluiddevicemapsenabled, // q: ulong
    processbreakontermination, // qs: ulong
    processdebugobjecthandle, // q: handle // 30
    processdebugflags, // qs: ulong
    processhandletracing, // q: process_handle_tracing_query; s: size 0 disables, otherwise enables
    processiopriority, // qs: io_priority_hint
    processexecuteflags, // qs: ulong
    processresourcemanagement,
    processcookie, // q: ulong
    processimageinformation, // q: section_image_information
    processcycletime, // q: process_cycle_time_information // since vista
    processpagepriority, // q: ulong
    processinstrumentationcallback, // 40
    processthreadstackallocation, // s: process_stack_allocation_information, process_stack_allocation_information_ex
    processworkingsetwatchex, // q: process_ws_watch_information_ex[]
    processimagefilenamewin32, // q: unicode_string
    processimagefilemapping, // q: handle (input)
    processaffinityupdatemode, // qs: process_affinity_update_mode
    processmemoryallocationmode, // qs: process_memory_allocation_mode
    processgroupinformation, // q: ushort[]
    processtokenvirtualizationenabled, // s: ulong
    processconsolehostprocess, // q: ulong_ptr
    processwindowinformation, // q: process_window_information // 50
    processhandleinformation, // q: process_handle_snapshot_information // since win8
    processmitigationpolicy, // s: process_mitigation_policy_information
    processdynamicfunctiontableinformation,
    processhandlecheckingmode,
    processkeepalivecount, // q: process_keepalive_count_information
    processrevokefilehandles, // s: process_revoke_file_handles_information
    processworkingsetcontrol, // s: process_working_set_control
    processhandletable, // since winblue
    processcheckstackextentsmode,
    processcommandlineinformation, // q: unicode_string // 60
    processprotectioninformation, // q: ps_protection
    processmemoryexhaustion, // process_memory_exhaustion_info // since threshold
    processfaultinformation, // process_fault_information
    processtelemetryidinformation, // process_telemetry_id_information
    processcommitreleaseinformation, // process_commit_release_information
    processdefaultcpusetsinformation,
    processallowedcpusetsinformation,
    processsubsystemprocess,
    processjobmemoryinformation, // process_job_memory_info
    processinprivate, // since threshold2 // 70
    processraiseumexceptiononinvalidhandleclose,
    processiumchallengeresponse,
    processchildprocessinformation, // process_child_process_information
    processhighgraphicspriorityinformation,
    processsubsysteminformation, // q: subsystem_information_type // since redstone2
    processenergyvalues, // process_energy_values, process_extended_energy_values
    processactivitythrottlestate, // process_activity_throttle_state
    processactivitythrottlepolicy, // process_activity_throttle_policy
    processwin32ksyscallfilterinformation,
    processdisablesystemallowedcpusets,
    processwakeinformation, // process_wake_information
    processenergytrackingstate, // process_energy_tracking_state
    maxprocessinfoclass
} processinfoclass;


typedef enum _threadinfoclass
{
    threadbasicinformation, // q: thread_basic_information
    threadtimes, // q: kernel_user_times
    threadpriority, // s: kpriority
    threadbasepriority, // s: long
    threadaffinitymask, // s: kaffinity
    threadimpersonationtoken, // s: handle
    threaddescriptortableentry, // q: descriptor_table_entry (or wow64_descriptor_table_entry)
    threadenablealignmentfaultfixup, // s: boolean
    threadeventpair,
    threadquerysetwin32startaddress, // q: pvoid
    threadzerotlscell, // 10
    threadperformancecount, // q: large_integer
    threadamilastthread, // q: ulong
    threadidealprocessor, // s: ulong
    threadpriorityboost, // qs: ulong
    threadsettlsarrayaddress,
    threadisiopending, // q: ulong
    threadhidefromdebugger, // s: void
    threadbreakontermination, // qs: ulong
    threadswitchlegacystate,
    threadisterminated, // q: ulong // 20
    threadlastsystemcall, // q: thread_last_syscall_information
    threadiopriority, // qs: io_priority_hint
    threadcycletime, // q: thread_cycle_time_information
    threadpagepriority, // q: ulong
    threadactualbasepriority,
    threadtebinformation, // q: thread_teb_information (requires thread_get_context + thread_set_context)
    threadcswitchmon,
    threadcswitchpmu,
    threadwow64context, // q: wow64_context
    threadgroupinformation, // q: group_affinity // 30
    threadumsinformation, // q: thread_ums_information
    threadcounterprofiling,
    threadidealprocessorex, // q: processor_number
    threadcpuaccountinginformation, // since win8
    threadsuspendcount, // since winblue
    threadheterogeneouscpupolicy, // q: khetero_cpu_policy // since threshold
    threadcontainerid, // q: guid
    threadnameinformation, // qs: thread_name_information
    threadselectedcpusets,
    threadsystemthreadinformation, // q: system_thread_information // 40
    threadactualgroupaffinity, // since threshold2
    threaddynamiccodepolicyinfo,
    threadexplicitcasesensitivity,
    threadworkonbehalfticket,
    threadsubsysteminformation, // q: subsystem_information_type // since redstone2
    threaddbgkwerreportactive,
    threadattachcontainer,
    maxthreadinfoclass
} threadinfoclass;

typedef struct _SYSTEM_POOLTAG
{
    union
    {
        UCHAR Tag[ 4 ];
        ULONG TagUlong;
    };
    ULONG PagedAllocs;
    ULONG PagedFrees;
    SIZE_T PagedUsed;
    ULONG NonPagedAllocs;
    ULONG NonPagedFrees;
    SIZE_T NonPagedUsed;
}SYSTEM_POOLTAG, * PSYSTEM_POOLTAG;

typedef struct _SYSTEM_POOLTAG_INFORMATION
{
    ULONG Count;
    SYSTEM_POOLTAG TagInfo[ ANYSIZE_ARRAY ];
}SYSTEM_POOLTAG_INFORMATION, * PSYSTEM_POOLTAG_INFORMATION;

typedef struct _ldr_data_table_entry
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[ 4 ];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ReservedFlags5 : 3;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        } s;
    } u;
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
    PVOID Lock;
    void* DdagNode;
    LIST_ENTRY NodeModuleLink;
    struct _LDRP_LOAD_CONTEXT* LoadContext;
    PVOID ParentDllBase;
    PVOID SwitchBackContext;
    void* BaseAddressIndexNode;
    void* MappingInfoIndexNode;
    ULONG_PTR OriginalBase;
    LARGE_INTEGER LoadTime;
    ULONG BaseNameHashValue;
    void* LoadReason;
    ULONG ImplicitPathOptions;
    ULONG ReferenceCount;
    ULONG DependentLoadFlags;
    UCHAR SigningLevel; // Since Windows 10 RS2
} ldr_data_table_entry, * pldr_data_table_entry;

typedef enum _SYSTEM_FIRMWARE_TABLE_ACTION
{
    SystemFirmwareTable_Enumerate,
    SystemFirmwareTable_Get
} SYSTEM_FIRMWARE_TABLE_ACTION, * PSYSTEM_FIRMWARE_TABLE_ACTION;

typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION
{
    ULONG ProviderSignature;
    SYSTEM_FIRMWARE_TABLE_ACTION Action;
    ULONG TableID;
    ULONG TableBufferLength;
    UCHAR TableBuffer[ ANYSIZE_ARRAY ];
} SYSTEM_FIRMWARE_TABLE_INFORMATION, * PSYSTEM_FIRMWARE_TABLE_INFORMATION;

typedef enum _SYSDBG_COMMAND
{
    SysDbgQueryModuleInformation,
    SysDbgQueryTraceInformation,
    SysDbgSetTracepoint,
    SysDbgSetSpecialCall,
    SysDbgClearSpecialCalls,
    SysDbgQuerySpecialCalls,
    SysDbgBreakPoint,
    SysDbgQueryVersion,
    SysDbgReadVirtual,
    SysDbgWriteVirtual,
    SysDbgReadPhysical,
    SysDbgWritePhysical,
    SysDbgReadControlSpace,
    SysDbgWriteControlSpace,
    SysDbgReadIoSpace,
    SysDbgWriteIoSpace,
    SysDbgReadMsr,
    SysDbgWriteMsr,
    SysDbgReadBusData,
    SysDbgWriteBusData,
    SysDbgCheckLowMemory,
    SysDbgEnableKernelDebugger,
    SysDbgDisableKernelDebugger,
    SysDbgGetAutoKdEnable,
    SysDbgSetAutoKdEnable,
    SysDbgGetPrintBufferSize,
    SysDbgSetPrintBufferSize,
    SysDbgGetKdUmExceptionEnable,
    SysDbgSetKdUmExceptionEnable,
    SysDbgGetTriageDump,
    SysDbgGetKdBlockEnable,
    SysDbgSetKdBlockEnable,
} SYSDBG_COMMAND, * PSYSDBG_COMMAND;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[ 1 ];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _rtl_process_module_information
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[ 256 ];
} rtl_process_module_information, * prtl_process_module_information;

typedef struct _rtl_process_modules
{
    ULONG NumberOfModules;
    rtl_process_module_information Modules[ 1 ];
} rtl_process_modules, * prtl_process_modules;

typedef struct _teb
{
    NT_TIB NtTib;

    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;

    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[ 26 ];
    ULONG UserReserved[ 5 ];
    PVOID WOW32Reserved;
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID ReservedForDebuggerInstrumentation[ 16 ];
#ifdef _WIN64
    PVOID SystemReserved1[ 30 ];
#else
    PVOID SystemReserved1[ 26 ];
#endif
    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderReserved[ 11 ];
    ULONG ProxiedProcessId;
    void* ActivationStack;

    UCHAR WorkingOnBehalfTicket[ 8 ];
    NTSTATUS ExceptionCode;

    void* ActivationContextStackPointer;
    ULONG_PTR InstrumentationCallbackSp;
    ULONG_PTR InstrumentationCallbackPreviousPc;
    ULONG_PTR InstrumentationCallbackPreviousSp;
#ifdef _WIN64
    ULONG TxFsContext;
#endif
    BOOLEAN InstrumentationCallbackDisabled;
#ifndef _WIN64
    UCHAR SpareBytes[ 23 ];
    ULONG TxFsContext;
#endif
    void* GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    ULONG_PTR Win32ClientInfo[ 62 ];
    PVOID glDispatchTable[ 233 ];
    ULONG_PTR glReserved1[ 29 ];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;

    NTSTATUS LastStatusValue;
    UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[ 261 ];

    PVOID DeallocationStack;
    PVOID TlsSlots[ 64 ];
    LIST_ENTRY TlsLinks;

    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[ 2 ];

    ULONG HardErrorMode;
#ifdef _WIN64
    PVOID Instrumentation[ 11 ];
#else
    PVOID Instrumentation[ 9 ];
#endif
    GUID ActivityId;

    PVOID SubProcessTag;
    PVOID PerflibData;
    PVOID EtwTraceData;
    PVOID WinSockData;
    ULONG GdiBatchCount;

    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        } s1;
    } u1;

    ULONG GuaranteedStackBytes;
    PVOID ReservedForPerf;
    PVOID ReservedForOle;
    ULONG WaitingOnLoaderLock;
    PVOID SavedPriorityState;
    ULONG_PTR ReservedForCodeCoverage;
    PVOID ThreadPoolData;
    PVOID* TlsExpansionSlots;
#ifdef _WIN64
    PVOID DeallocationBStore;
    PVOID BStoreLimit;
#endif
    ULONG MuiGeneration;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    USHORT HeapVirtualAffinity;
    USHORT LowFragHeapDataSlot;
    HANDLE CurrentTransactionHandle;
    void* ActiveFrame;
    PVOID FlsData;

    PVOID PreferredLanguages;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;

    union
    {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    } u2;
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;
            USHORT HasFiberData : 1;
            USHORT SkipThreadAttach : 1;
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;
            USHORT ClonedThread : 1;
            USHORT SuppressDebugMsg : 1;
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;
            USHORT SessionAware : 1;
            USHORT LoadOwner : 1;
            USHORT LoaderWorker : 1;
            USHORT SkipLoaderInit : 1;
            USHORT SpareSameTebBits : 1;
        } s2;
    } u3;

    PVOID TxnScopeEnterCallback;
    PVOID TxnScopeExitCallback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    LONG WowTebOffset;
    PVOID ResourceRetValue;
    PVOID ReservedForWdf;
    ULONGLONG ReservedForCrt;
    GUID EffectiveContainerId;
} teb, * pteb;


__forceinline struct _teb* nt_current_teb( )
{
    return ( struct _teb* ) __readgsqword( FIELD_OFFSET( NT_TIB, Self ) );
}