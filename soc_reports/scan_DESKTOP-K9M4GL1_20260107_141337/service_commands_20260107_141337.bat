@echo off
REM SOC Incident responder - Service Commands
REM Generated: 2026-01-07 14:13:37
REM Run as Administrator

echo ========================================
echo  SOC Security Analyzer Service Actions
echo ========================================

REM HIGH PRIORITY SERVICE ACTIONS
REM ENSURE DISABLED: COM+ Event System
sc config "EventSystem" start= disabled

REM ENSURE DISABLED: NVIDIA LocalSystem Container
sc config "NvContainerLocalSystem" start= disabled

REM ENSURE DISABLED: NVIDIA Display Container LS
sc config "NVDisplay.ContainerLocalSystem" start= disabled

REM ENSURE DISABLED: System Events Broker
sc config "SystemEventsBroker" start= disabled

REM ENSURE DISABLED: Diagnostic System Host
sc config "WdiSystemHost" start= disabled

REM INVESTIGATE suspicious service: Autodesk Desktop Licensing Service
sc query "AdskLicensingService"
wmic service where name="AdskLicensingService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Application Layer Gateway Service
sc query "ALG"
wmic service where name="ALG" get *
Check file signature and location

REM INVESTIGATE suspicious service: AnyDesk Service
sc query "AnyDesk"
wmic service where name="AnyDesk" get *
Check file signature and location

REM INVESTIGATE suspicious service: Application Identity
sc query "AppIDSvc"
wmic service where name="AppIDSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Application Information
sc query "Appinfo"
wmic service where name="Appinfo" get *
Check file signature and location

REM INVESTIGATE suspicious service: App Readiness
sc query "AppReadiness"
wmic service where name="AppReadiness" get *
Check file signature and location

REM INVESTIGATE suspicious service: AppX Deployment Service (AppXSVC)
sc query "AppXSvc"
wmic service where name="AppXSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Virtual Audio Device Proxy Service
sc query "ApxSvc"
wmic service where name="ApxSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: AtherosSvc
sc query "AtherosSvc"
wmic service where name="AtherosSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Audio Endpoint Builder
sc query "AudioEndpointBuilder"
wmic service where name="AudioEndpointBuilder" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Audio
sc query "Audiosrv"
wmic service where name="Audiosrv" get *
Check file signature and location

REM INVESTIGATE suspicious service: Autodesk Access Service Host
sc query "Autodesk Access Service Host"
wmic service where name="Autodesk Access Service Host" get *
Check file signature and location

REM INVESTIGATE suspicious service: Cellular Time
sc query "autotimesvc"
wmic service where name="autotimesvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: ActiveX Installer (AxInstSV)
sc query "AxInstSV"
wmic service where name="AxInstSV" get *
Check file signature and location

REM INVESTIGATE suspicious service: BitLocker Drive Encryption Service
sc query "BDESVC"
wmic service where name="BDESVC" get *
Check file signature and location

REM INVESTIGATE suspicious service: Base Filtering Engine
sc query "BFE"
wmic service where name="BFE" get *
Check file signature and location

REM INVESTIGATE suspicious service: Background Intelligent Transfer Service
sc query "BITS"
wmic service where name="BITS" get *
Check file signature and location

REM INVESTIGATE suspicious service: Brave Update Service (brave)
sc query "brave"
wmic service where name="brave" get *
Check file signature and location

REM INVESTIGATE suspicious service: Brave Elevation Service (BraveElevationService)
sc query "BraveElevationService"
wmic service where name="BraveElevationService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Brave Update Service (bravem)
sc query "bravem"
wmic service where name="bravem" get *
Check file signature and location

REM INVESTIGATE suspicious service: Background Tasks Infrastructure Service
sc query "BrokerInfrastructure"
wmic service where name="BrokerInfrastructure" get *
Check file signature and location

REM INVESTIGATE suspicious service: Computer Browser
sc query "Browser"
wmic service where name="Browser" get *
Check file signature and location

REM INVESTIGATE suspicious service: Bluetooth Audio Gateway Service
sc query "BTAGService"
wmic service where name="BTAGService" get *
Check file signature and location

REM INVESTIGATE suspicious service: AVCTP service
sc query "BthAvctpSvc"
wmic service where name="BthAvctpSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Bluetooth Support Service
sc query "bthserv"
wmic service where name="bthserv" get *
Check file signature and location

REM INVESTIGATE suspicious service: Capability Access Manager Service
sc query "camsvc"
wmic service where name="camsvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Connected Devices Platform Service
sc query "CDPSvc"
wmic service where name="CDPSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Certificate Propagation
sc query "CertPropSvc"
wmic service where name="CertPropSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Client License Service (ClipSVC)
sc query "ClipSVC"
wmic service where name="ClipSVC" get *
Check file signature and location

REM INVESTIGATE suspicious service: COM+ System Application
sc query "COMSysApp"
wmic service where name="COMSysApp" get *
Check file signature and location

REM INVESTIGATE suspicious service: CoreMessaging
sc query "CoreMessagingRegistrar"
wmic service where name="CoreMessagingRegistrar" get *
Check file signature and location

REM INVESTIGATE suspicious service: Intel(R) Content Protection HECI Service
sc query "cphs"
wmic service where name="cphs" get *
Check file signature and location

REM INVESTIGATE suspicious service: Intel(R) Content Protection HDCP Service
sc query "cplspcon"
wmic service where name="cplspcon" get *
Check file signature and location

REM INVESTIGATE suspicious service: Cryptographic Services
sc query "CryptSvc"
wmic service where name="CryptSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: DCOM Server Process Launcher
sc query "DcomLaunch"
wmic service where name="DcomLaunch" get *
Check file signature and location

REM INVESTIGATE suspicious service: Declared Configuration(DC) service
sc query "dcsvc"
wmic service where name="dcsvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Optimize drives
sc query "defragsvc"
wmic service where name="defragsvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Dell SupportAssist Remediation
sc query "Dell SupportAssist Remediation"
wmic service where name="Dell SupportAssist Remediation" get *
Check file signature and location

REM INVESTIGATE suspicious service: Device Association Service
sc query "DeviceAssociationService"
wmic service where name="DeviceAssociationService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Device Install Service
sc query "DeviceInstall"
wmic service where name="DeviceInstall" get *
Check file signature and location

REM INVESTIGATE suspicious service: DevQuery Background Discovery Broker
sc query "DevQueryBroker"
wmic service where name="DevQueryBroker" get *
Check file signature and location

REM INVESTIGATE suspicious service: Wondershare WSID help
sc query "DFWSIDService"
wmic service where name="DFWSIDService" get *
Check file signature and location

REM INVESTIGATE suspicious service: DHCP Client
sc query "Dhcp"
wmic service where name="Dhcp" get *
Check file signature and location

REM INVESTIGATE suspicious service: Diagnostic Execution Service
sc query "diagsvc"
wmic service where name="diagsvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Connected User Experiences and Telemetry
sc query "DiagTrack"
wmic service where name="DiagTrack" get *
Check file signature and location

REM INVESTIGATE suspicious service: Display Policy Service
sc query "DispBrokerDesktopSvc"
wmic service where name="DispBrokerDesktopSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Display Enhancement Service
sc query "DisplayEnhancementService"
wmic service where name="DisplayEnhancementService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Device Management Enrollment Service
sc query "DmEnrollmentSvc"
wmic service where name="DmEnrollmentSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Device Management Wireless Application Protocol (WAP) Push message Routing Service
sc query "dmwappushservice"
wmic service where name="dmwappushservice" get *
Check file signature and location

REM INVESTIGATE suspicious service: DNS Client
sc query "Dnscache"
wmic service where name="Dnscache" get *
Check file signature and location

REM INVESTIGATE suspicious service: Delivery Optimization
sc query "DoSvc"
wmic service where name="DoSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Wired AutoConfig
sc query "dot3svc"
wmic service where name="dot3svc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Diagnostic Policy Service
sc query "DPS"
wmic service where name="DPS" get *
Check file signature and location

REM INVESTIGATE suspicious service: Device Setup Manager
sc query "DsmSvc"
wmic service where name="DsmSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Data Sharing Service
sc query "DsSvc"
wmic service where name="DsSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Data Usage
sc query "DusmSvc"
wmic service where name="DusmSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Extensible Authentication Protocol
sc query "EapHost"
wmic service where name="EapHost" get *
Check file signature and location

REM INVESTIGATE suspicious service: Microsoft Edge Update Service (edgeupdate)
sc query "edgeupdate"
wmic service where name="edgeupdate" get *
Check file signature and location

REM INVESTIGATE suspicious service: Microsoft Edge Update Service (edgeupdatem)
sc query "edgeupdatem"
wmic service where name="edgeupdatem" get *
Check file signature and location

REM INVESTIGATE suspicious service: Encrypting File System (EFS)
sc query "EFS"
wmic service where name="EFS" get *
Check file signature and location

REM INVESTIGATE suspicious service: Embedded Mode
sc query "embeddedmode"
wmic service where name="embeddedmode" get *
Check file signature and location

REM INVESTIGATE suspicious service: Enterprise App Management Service
sc query "EntAppSvc"
wmic service where name="EntAppSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Intel(R) Dynamic Platform and Thermal Framework service
sc query "esifsvc"
wmic service where name="esifsvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Event Log
sc query "EventLog"
wmic service where name="EventLog" get *
Check file signature and location

REM INVESTIGATE suspicious service: Fax
sc query "Fax"
wmic service where name="Fax" get *
Check file signature and location

REM INVESTIGATE suspicious service: Function Discovery Provider Host
sc query "fdPHost"
wmic service where name="fdPHost" get *
Check file signature and location

REM INVESTIGATE suspicious service: Function Discovery Resource Publication
sc query "FDResPub"
wmic service where name="FDResPub" get *
Check file signature and location

REM INVESTIGATE suspicious service: File History Service
sc query "fhsvc"
wmic service where name="fhsvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: FlexNet Licensing Service 64
sc query "FlexNet Licensing Service 64"
wmic service where name="FlexNet Licensing Service 64" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Font Cache Service
sc query "FontCache"
wmic service where name="FontCache" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Presentation Foundation Font Cache 3.0.0.0
sc query "FontCache3.0.0.0"
wmic service where name="FontCache3.0.0.0" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Camera Frame Server
sc query "FrameServer"
wmic service where name="FrameServer" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Camera Frame Server Monitor
sc query "FrameServerMonitor"
wmic service where name="FrameServerMonitor" get *
Check file signature and location

REM INVESTIGATE suspicious service: GameInput Service
sc query "GameInputSvc"
wmic service where name="GameInputSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Google Chrome Elevation Service (GoogleChromeElevationService)
sc query "GoogleChromeElevationService"
wmic service where name="GoogleChromeElevationService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Google Updater Internal Service (GoogleUpdaterInternalService141.0.7340.0)
sc query "GoogleUpdaterInternalService141.0.7340.0"
wmic service where name="GoogleUpdaterInternalService141.0.7340.0" get *
Check file signature and location

REM INVESTIGATE suspicious service: Google Updater Service (GoogleUpdaterService141.0.7340.0)
sc query "GoogleUpdaterService141.0.7340.0"
wmic service where name="GoogleUpdaterService141.0.7340.0" get *
Check file signature and location

REM INVESTIGATE suspicious service: Group Policy Client
sc query "gpsvc"
wmic service where name="gpsvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: GraphicsPerfSvc
sc query "GraphicsPerfSvc"
wmic service where name="GraphicsPerfSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Intel(R) RST HFC Disable Service
sc query "HfcDisableService"
wmic service where name="HfcDisableService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Human Interface Device Service
sc query "hidserv"
wmic service where name="hidserv" get *
Check file signature and location

REM INVESTIGATE suspicious service: HV Host Service
sc query "HvHost"
wmic service where name="HvHost" get *
Check file signature and location

REM INVESTIGATE suspicious service: Intel(R) Optane(TM) Memory Service
sc query "iaStorAfsService"
wmic service where name="iaStorAfsService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Intel(R) Rapid Storage Technology
sc query "IAStorDataMgrSvc"
wmic service where name="IAStorDataMgrSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Mobile Hotspot Service
sc query "icssvc"
wmic service where name="icssvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Intel(R) Graphics Command Center Service
sc query "igccservice"
wmic service where name="igccservice" get *
Check file signature and location

REM INVESTIGATE suspicious service: Intel(R) HD Graphics Control Panel Service
sc query "igfxCUIService2.0.0.0"
wmic service where name="igfxCUIService2.0.0.0" get *
Check file signature and location

REM INVESTIGATE suspicious service: IKE and AuthIP IPsec Keying Modules
sc query "IKEEXT"
wmic service where name="IKEEXT" get *
Check file signature and location

REM INVESTIGATE suspicious service: Microsoft Store Install Service
sc query "InstallService"
wmic service where name="InstallService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Intel(R) Capability Licensing Service TCP IP Interface
sc query "Intel(R) Capability Licensing Service TCP IP Interface"
wmic service where name="Intel(R) Capability Licensing Service TCP IP Interface" get *
Check file signature and location

REM INVESTIGATE suspicious service: Intel(R) TPM Provisioning Service
sc query "Intel(R) TPM Provisioning Service"
wmic service where name="Intel(R) TPM Provisioning Service" get *
Check file signature and location

REM INVESTIGATE suspicious service: Inventory and Compatibility Appraisal service
sc query "InventorySvc"
wmic service where name="InventorySvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: IP Helper
sc query "iphlpsvc"
wmic service where name="iphlpsvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: IP Translation Configuration Service
sc query "IpxlatCfgSvc"
wmic service where name="IpxlatCfgSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Intel(R) Dynamic Application Loader Host Interface Service
sc query "jhi_service"
wmic service where name="jhi_service" get *
Check file signature and location

REM INVESTIGATE suspicious service: CNG Key Isolation
sc query "KeyIso"
wmic service where name="KeyIso" get *
Check file signature and location

REM INVESTIGATE suspicious service: Killer Network Service
sc query "Killer Network Service"
wmic service where name="Killer Network Service" get *
Check file signature and location

REM INVESTIGATE suspicious service: KNDBWM
sc query "KNDBWM"
wmic service where name="KNDBWM" get *
Check file signature and location

REM INVESTIGATE suspicious service: KtmRm for Distributed Transaction Coordinator
sc query "KtmRm"
wmic service where name="KtmRm" get *
Check file signature and location

REM INVESTIGATE suspicious service: Server
sc query "LanmanServer"
wmic service where name="LanmanServer" get *
Check file signature and location

REM INVESTIGATE suspicious service: Workstation
sc query "LanmanWorkstation"
wmic service where name="LanmanWorkstation" get *
Check file signature and location

REM INVESTIGATE suspicious service: Geolocation Service
sc query "lfsvc"
wmic service where name="lfsvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows License Manager Service
sc query "LicenseManager"
wmic service where name="LicenseManager" get *
Check file signature and location

REM INVESTIGATE suspicious service: Link-Layer Topology Discovery Mapper
sc query "lltdsvc"
wmic service where name="lltdsvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: TCP/IP NetBIOS Helper
sc query "lmhosts"
wmic service where name="lmhosts" get *
Check file signature and location

REM INVESTIGATE suspicious service: Intel(R) Management and Security Application Local Management Service
sc query "LMS"
wmic service where name="LMS" get *
Check file signature and location

REM INVESTIGATE suspicious service: Kerberos Local Key Distribution Center
sc query "LocalKdc"
wmic service where name="LocalKdc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Local Session Manager
sc query "LSM"
wmic service where name="LSM" get *
Check file signature and location

REM INVESTIGATE suspicious service: Language Experience Service
sc query "LxpSvc"
wmic service where name="LxpSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Downloaded Maps Manager
sc query "MapsBroker"
wmic service where name="MapsBroker" get *
Check file signature and location

REM INVESTIGATE suspicious service: McpManagementService
sc query "McpManagementService"
wmic service where name="McpManagementService" get *
Check file signature and location

REM INVESTIGATE suspicious service: MDCoreSvc
sc query "MDCoreSvc"
wmic service where name="MDCoreSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Microsoft Edge Elevation Service (MicrosoftEdgeElevationService)
sc query "MicrosoftEdgeElevationService"
wmic service where name="MicrosoftEdgeElevationService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Defender Firewall
sc query "mpssvc"
wmic service where name="mpssvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Distributed Transaction Coordinator
sc query "MSDTC"
wmic service where name="MSDTC" get *
Check file signature and location

REM INVESTIGATE suspicious service: Microsoft iSCSI Initiator Service
sc query "MSiSCSI"
wmic service where name="MSiSCSI" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Installer
sc query "msiserver"
wmic service where name="msiserver" get *
Check file signature and location

REM INVESTIGATE suspicious service: Natural Authentication
sc query "NaturalAuthentication"
wmic service where name="NaturalAuthentication" get *
Check file signature and location

REM INVESTIGATE suspicious service: Network Connectivity Assistant
sc query "NcaSvc"
wmic service where name="NcaSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Network Connection Broker
sc query "NcbService"
wmic service where name="NcbService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Network Connected Devices Auto-Setup
sc query "NcdAutoSetup"
wmic service where name="NcdAutoSetup" get *
Check file signature and location

REM INVESTIGATE suspicious service: Netlogon
sc query "Netlogon"
wmic service where name="Netlogon" get *
Check file signature and location

REM INVESTIGATE suspicious service: Network Connections
sc query "Netman"
wmic service where name="Netman" get *
Check file signature and location

REM INVESTIGATE suspicious service: Network List Service
sc query "netprofm"
wmic service where name="netprofm" get *
Check file signature and location

REM INVESTIGATE suspicious service: Network Setup Service
sc query "NetSetupSvc"
wmic service where name="NetSetupSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Net.Tcp Port Sharing Service
sc query "NetTcpPortSharing"
wmic service where name="NetTcpPortSharing" get *
Check file signature and location

REM INVESTIGATE suspicious service: Microsoft Passport Container
sc query "NgcCtnrSvc"
wmic service where name="NgcCtnrSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Microsoft Passport
sc query "NgcSvc"
wmic service where name="NgcSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Network Location Awareness
sc query "NlaSvc"
wmic service where name="NlaSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Network Store Interface Service
sc query "nsi"
wmic service where name="nsi" get *
Check file signature and location

REM INVESTIGATE suspicious service: NVIDIA NetworkService Container
sc query "NvContainerNetworkService"
wmic service where name="NvContainerNetworkService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Office 64 Source Engine
sc query "ose64"
wmic service where name="ose64" get *
Check file signature and location

REM INVESTIGATE suspicious service: Program Compatibility Assistant Service
sc query "PcaSvc"
wmic service where name="PcaSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Perception Simulation Service
sc query "perceptionsimulation"
wmic service where name="perceptionsimulation" get *
Check file signature and location

REM INVESTIGATE suspicious service: Performance Counter DLL Host
sc query "PerfHost"
wmic service where name="PerfHost" get *
Check file signature and location

REM INVESTIGATE suspicious service: Phone Service
sc query "PhoneSvc"
wmic service where name="PhoneSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Performance Logs & Alerts
sc query "pla"
wmic service where name="pla" get *
Check file signature and location

REM INVESTIGATE suspicious service: Plug and Play
sc query "PlugPlay"
wmic service where name="PlugPlay" get *
Check file signature and location

REM INVESTIGATE suspicious service: IPsec Policy Agent
sc query "PolicyAgent"
wmic service where name="PolicyAgent" get *
Check file signature and location

REM INVESTIGATE suspicious service: Power
sc query "Power"
wmic service where name="Power" get *
Check file signature and location

REM INVESTIGATE suspicious service: Print Device Configuration Service
sc query "PrintDeviceConfigurationService"
wmic service where name="PrintDeviceConfigurationService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Printer Extensions and Notifications
sc query "PrintNotify"
wmic service where name="PrintNotify" get *
Check file signature and location

REM INVESTIGATE suspicious service: PrintScanBrokerService
sc query "PrintScanBrokerService"
wmic service where name="PrintScanBrokerService" get *
Check file signature and location

REM INVESTIGATE suspicious service: User Profile Service
sc query "ProfSvc"
wmic service where name="ProfSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows PushToInstall Service
sc query "PushToInstall"
wmic service where name="PushToInstall" get *
Check file signature and location

REM INVESTIGATE suspicious service: Qualcomm Atheros WLAN Driver Service
sc query "QcomWlanSrv"
wmic service where name="QcomWlanSrv" get *
Check file signature and location

REM INVESTIGATE suspicious service: Quality Windows Audio Video Experience
sc query "QWAVE"
wmic service where name="QWAVE" get *
Check file signature and location

REM INVESTIGATE suspicious service: Remote Access Auto Connection Manager
sc query "RasAuto"
wmic service where name="RasAuto" get *
Check file signature and location

REM INVESTIGATE suspicious service: Remote Access Connection Manager
sc query "RasMan"
wmic service where name="RasMan" get *
Check file signature and location

REM INVESTIGATE suspicious service: ReFS Dedup Service
sc query "refsdedupsvc"
wmic service where name="refsdedupsvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Routing and Remote Access
sc query "RemoteAccess"
wmic service where name="RemoteAccess" get *
Check file signature and location

REM INVESTIGATE suspicious service: RemoteMouseService
sc query "RemoteMouseService"
wmic service where name="RemoteMouseService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Remote Registry
sc query "RemoteRegistry"
wmic service where name="RemoteRegistry" get *
Check file signature and location

REM INVESTIGATE suspicious service: Retail Demo Service
sc query "RetailDemo"
wmic service where name="RetailDemo" get *
Check file signature and location

REM INVESTIGATE suspicious service: Radio Management Service
sc query "RmSvc"
wmic service where name="RmSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: RPC Endpoint Mapper
sc query "RpcEptMapper"
wmic service where name="RpcEptMapper" get *
Check file signature and location

REM INVESTIGATE suspicious service: Remote Procedure Call (RPC) Locator
sc query "RpcLocator"
wmic service where name="RpcLocator" get *
Check file signature and location

REM INVESTIGATE suspicious service: Remote Procedure Call (RPC)
sc query "RpcSs"
wmic service where name="RpcSs" get *
Check file signature and location

REM INVESTIGATE suspicious service: RstMwService
sc query "RstMwService"
wmic service where name="RstMwService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Realtek Audio Service
sc query "RtkAudioService"
wmic service where name="RtkAudioService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Security Accounts Manager
sc query "SamSs"
wmic service where name="SamSs" get *
Check file signature and location

REM INVESTIGATE suspicious service: Smart Card
sc query "SCardSvr"
wmic service where name="SCardSvr" get *
Check file signature and location

REM INVESTIGATE suspicious service: Smart Card Device Enumeration Service
sc query "ScDeviceEnum"
wmic service where name="ScDeviceEnum" get *
Check file signature and location

REM INVESTIGATE suspicious service: Task Scheduler
sc query "Schedule"
wmic service where name="Schedule" get *
Check file signature and location

REM INVESTIGATE suspicious service: Smart Card Removal Policy
sc query "SCPolicySvc"
wmic service where name="SCPolicySvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Backup
sc query "SDRSVC"
wmic service where name="SDRSVC" get *
Check file signature and location

REM INVESTIGATE suspicious service: Secondary Logon
sc query "seclogon"
wmic service where name="seclogon" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Security Service
sc query "SecurityHealthService"
wmic service where name="SecurityHealthService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Payments and NFC/SE Manager
sc query "SEMgrSvc"
wmic service where name="SEMgrSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: System Event Notification Service
sc query "SENS"
wmic service where name="SENS" get *
Check file signature and location

REM INVESTIGATE suspicious service: Sensor Data Service
sc query "SensorDataService"
wmic service where name="SensorDataService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Sensor Service
sc query "SensorService"
wmic service where name="SensorService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Sensor Monitoring Service
sc query "SensrSvc"
wmic service where name="SensrSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Remote Desktop Configuration
sc query "SessionEnv"
wmic service where name="SessionEnv" get *
Check file signature and location

REM INVESTIGATE suspicious service: SoftEther VPN Server
sc query "SEVPNSERVER"
wmic service where name="SEVPNSERVER" get *
Check file signature and location

REM INVESTIGATE suspicious service: System Guard Runtime Monitor Broker
sc query "SgrmBroker"
wmic service where name="SgrmBroker" get *
Check file signature and location

REM INVESTIGATE suspicious service: Internet Connection Sharing (ICS)
sc query "SharedAccess"
wmic service where name="SharedAccess" get *
Check file signature and location

REM INVESTIGATE suspicious service: Shell Hardware Detection
sc query "ShellHWDetection"
wmic service where name="ShellHWDetection" get *
Check file signature and location

REM INVESTIGATE suspicious service: Shared PC Account Manager
sc query "shpamsvc"
wmic service where name="shpamsvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Microsoft Storage Spaces SMP
sc query "smphost"
wmic service where name="smphost" get *
Check file signature and location

REM INVESTIGATE suspicious service: Microsoft Windows SMS Router Service.
sc query "SmsRouter"
wmic service where name="SmsRouter" get *
Check file signature and location

REM INVESTIGATE suspicious service: SNMP Trap
sc query "SNMPTrap"
wmic service where name="SNMPTrap" get *
Check file signature and location

REM INVESTIGATE suspicious service: Print Spooler
sc query "Spooler"
wmic service where name="Spooler" get *
Check file signature and location

REM INVESTIGATE suspicious service: Software Protection
sc query "sppsvc"
wmic service where name="sppsvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: SSDP Discovery
sc query "SSDPSRV"
wmic service where name="SSDPSRV" get *
Check file signature and location

REM INVESTIGATE suspicious service: OpenSSH Authentication Agent
sc query "ssh-agent"
wmic service where name="ssh-agent" get *
Check file signature and location

REM INVESTIGATE suspicious service: Secure Socket Tunneling Protocol Service
sc query "SstpSvc"
wmic service where name="SstpSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: State Repository Service
sc query "StateRepository"
wmic service where name="StateRepository" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Image Acquisition (WIA)
sc query "StiSvc"
wmic service where name="StiSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Storage Service
sc query "StorSvc"
wmic service where name="StorSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Spot Verifier
sc query "svsvc"
wmic service where name="svsvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Microsoft Software Shadow Copy Provider
sc query "swprv"
wmic service where name="swprv" get *
Check file signature and location

REM INVESTIGATE suspicious service: SynTPEnh Caller Service
sc query "SynTPEnhService"
wmic service where name="SynTPEnhService" get *
Check file signature and location

REM INVESTIGATE suspicious service: SysMain
sc query "SysMain"
wmic service where name="SysMain" get *
Check file signature and location

REM INVESTIGATE suspicious service: Telephony
sc query "TapiSrv"
wmic service where name="TapiSrv" get *
Check file signature and location

REM INVESTIGATE suspicious service: Remote Desktop Services
sc query "TermService"
wmic service where name="TermService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Text Input Management Service
sc query "TextInputManagementService"
wmic service where name="TextInputManagementService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Themes
sc query "Themes"
wmic service where name="Themes" get *
Check file signature and location

REM INVESTIGATE suspicious service: Thunderbolt(TM) Service
sc query "ThunderboltService"
wmic service where name="ThunderboltService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Storage Tiers Management
sc query "TieringEngineService"
wmic service where name="TieringEngineService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Time Broker
sc query "TimeBrokerSvc"
wmic service where name="TimeBrokerSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Web Account Manager
sc query "TokenBroker"
wmic service where name="TokenBroker" get *
Check file signature and location

REM INVESTIGATE suspicious service: Distributed Link Tracking Client
sc query "TrkWks"
wmic service where name="TrkWks" get *
Check file signature and location

REM INVESTIGATE suspicious service: Recommended Troubleshooting Service
sc query "TroubleshootingSvc"
wmic service where name="TroubleshootingSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Modules Installer
sc query "TrustedInstaller"
wmic service where name="TrustedInstaller" get *
Check file signature and location

REM INVESTIGATE suspicious service: Auto Time Zone Updater
sc query "tzautoupdate"
wmic service where name="tzautoupdate" get *
Check file signature and location

REM INVESTIGATE suspicious service: Remote Desktop Services UserMode Port Redirector
sc query "UmRdpService"
wmic service where name="UmRdpService" get *
Check file signature and location

REM INVESTIGATE suspicious service: UPnP Device Host
sc query "upnphost"
wmic service where name="upnphost" get *
Check file signature and location

REM INVESTIGATE suspicious service: User Manager
sc query "UserManager"
wmic service where name="UserManager" get *
Check file signature and location

REM INVESTIGATE suspicious service: Update Orchestrator Service
sc query "UsoSvc"
wmic service where name="UsoSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Credential Manager
sc query "VaultSvc"
wmic service where name="VaultSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: VirtualBox system service
sc query "VBoxSDS"
wmic service where name="VBoxSDS" get *
Check file signature and location

REM INVESTIGATE suspicious service: VirtualBox Guest Additions Service
sc query "VBoxService"
wmic service where name="VBoxService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Virtual Disk
sc query "vds"
wmic service where name="vds" get *
Check file signature and location

REM INVESTIGATE suspicious service: Hyper-V Guest Service Interface
sc query "vmicguestinterface"
wmic service where name="vmicguestinterface" get *
Check file signature and location

REM INVESTIGATE suspicious service: Hyper-V Heartbeat Service
sc query "vmicheartbeat"
wmic service where name="vmicheartbeat" get *
Check file signature and location

REM INVESTIGATE suspicious service: Hyper-V Data Exchange Service
sc query "vmickvpexchange"
wmic service where name="vmickvpexchange" get *
Check file signature and location

REM INVESTIGATE suspicious service: Hyper-V Remote Desktop Virtualization Service
sc query "vmicrdv"
wmic service where name="vmicrdv" get *
Check file signature and location

REM INVESTIGATE suspicious service: Hyper-V Guest Shutdown Service
sc query "vmicshutdown"
wmic service where name="vmicshutdown" get *
Check file signature and location

REM INVESTIGATE suspicious service: Hyper-V Time Synchronization Service
sc query "vmictimesync"
wmic service where name="vmictimesync" get *
Check file signature and location

REM INVESTIGATE suspicious service: Hyper-V PowerShell Direct Service
sc query "vmicvmsession"
wmic service where name="vmicvmsession" get *
Check file signature and location

REM INVESTIGATE suspicious service: Hyper-V Volume Shadow Copy Requestor
sc query "vmicvss"
wmic service where name="vmicvss" get *
Check file signature and location

REM INVESTIGATE suspicious service: Visual Studio Installer Elevation Service
sc query "VSInstallerElevationService"
wmic service where name="VSInstallerElevationService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Volume Shadow Copy
sc query "VSS"
wmic service where name="VSS" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Time
sc query "W32Time"
wmic service where name="W32Time" get *
Check file signature and location

REM INVESTIGATE suspicious service: WaaSMedicSvc
sc query "WaaSMedicSvc"
wmic service where name="WaaSMedicSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: WalletService
sc query "WalletService"
wmic service where name="WalletService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Warp JIT Service
sc query "WarpJITSvc"
wmic service where name="WarpJITSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Block Level Backup Engine Service
sc query "wbengine"
wmic service where name="wbengine" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Biometric Service
sc query "WbioSrvc"
wmic service where name="WbioSrvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Connection Manager
sc query "Wcmsvc"
wmic service where name="Wcmsvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Connect Now - Config Registrar
sc query "wcncsvc"
wmic service where name="wcncsvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Diagnostic Service Host
sc query "WdiServiceHost"
wmic service where name="WdiServiceHost" get *
Check file signature and location

REM INVESTIGATE suspicious service: Microsoft Defender Antivirus Network Inspection Service
sc query "WdNisSvc"
wmic service where name="WdNisSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: WebClient
sc query "WebClient"
wmic service where name="WebClient" get *
Check file signature and location

REM INVESTIGATE suspicious service: Web Threat Defense Service
sc query "webthreatdefsvc"
wmic service where name="webthreatdefsvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Event Collector
sc query "Wecsvc"
wmic service where name="Wecsvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Encryption Provider Host Service
sc query "WEPHOSTSVC"
wmic service where name="WEPHOSTSVC" get *
Check file signature and location

REM INVESTIGATE suspicious service: Problem Reports Control Panel Support
sc query "wercplsupport"
wmic service where name="wercplsupport" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Error Reporting Service
sc query "WerSvc"
wmic service where name="WerSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Wi-Fi Direct Services Connection Manager Service
sc query "WFDSConMgrSvc"
wmic service where name="WFDSConMgrSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Still Image Acquisition Events
sc query "WiaRpc"
wmic service where name="WiaRpc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Microsoft Defender Antivirus Service
sc query "WinDefend"
wmic service where name="WinDefend" get *
Check file signature and location

REM INVESTIGATE suspicious service: WinHTTP Web Proxy Auto-Discovery Service
sc query "WinHttpAutoProxySvc"
wmic service where name="WinHttpAutoProxySvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Management Instrumentation
sc query "Winmgmt"
wmic service where name="Winmgmt" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Remote Management (WS-Management)
sc query "WinRM"
wmic service where name="WinRM" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Insider Service
sc query "wisvc"
wmic service where name="wisvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: WLAN AutoConfig
sc query "WlanSvc"
wmic service where name="WlanSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Microsoft Account Sign-in Assistant
sc query "wlidsvc"
wmic service where name="wlidsvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Local Profile Assistant Service
sc query "wlpasvc"
wmic service where name="wlpasvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Management Service
sc query "WManSvc"
wmic service where name="WManSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: WMI Performance Adapter
sc query "wmiApSrv"
wmic service where name="wmiApSrv" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Media Player Network Sharing Service
sc query "WMPNetworkSvc"
wmic service where name="WMPNetworkSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Work Folders
sc query "workfolderssvc"
wmic service where name="workfolderssvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Parental Controls
sc query "WpcMonSvc"
wmic service where name="WpcMonSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Portable Device Enumerator Service
sc query "WPDBusEnum"
wmic service where name="WPDBusEnum" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Push Notifications System Service
sc query "WpnService"
wmic service where name="WpnService" get *
Check file signature and location

REM INVESTIGATE suspicious service: WSAIFabricSvc
sc query "WSAIFabricSvc"
wmic service where name="WSAIFabricSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Security Center
sc query "wscsvc"
wmic service where name="wscsvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Search
sc query "WSearch"
wmic service where name="WSearch" get *
Check file signature and location

REM INVESTIGATE suspicious service: WSL Service
sc query "WSLService"
wmic service where name="WSLService" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Update
sc query "wuauserv"
wmic service where name="wuauserv" get *
Check file signature and location

REM INVESTIGATE suspicious service: WWAN AutoConfig
sc query "WwanSvc"
wmic service where name="WwanSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Xbox Live Auth Manager
sc query "XblAuthManager"
wmic service where name="XblAuthManager" get *
Check file signature and location

REM INVESTIGATE suspicious service: Xbox Live Game Save
sc query "XblGameSave"
wmic service where name="XblGameSave" get *
Check file signature and location

REM INVESTIGATE suspicious service: Xbox Accessory Management Service
sc query "XboxGipSvc"
wmic service where name="XboxGipSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Xbox Live Networking Service
sc query "XboxNetApiSvc"
wmic service where name="XboxNetApiSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Agent Activation Runtime_a094e
sc query "AarSvc_a094e"
wmic service where name="AarSvc_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: GameDVR and Broadcast User Service_a094e
sc query "BcastDVRUserService_a094e"
wmic service where name="BcastDVRUserService_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: Bluetooth User Support Service_a094e
sc query "BluetoothUserService_a094e"
wmic service where name="BluetoothUserService_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: CaptureService_a094e
sc query "CaptureService_a094e"
wmic service where name="CaptureService_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: Clipboard User Service_a094e
sc query "cbdhsvc_a094e"
wmic service where name="cbdhsvc_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: Connected Devices Platform User Service_a094e
sc query "CDPUserSvc_a094e"
wmic service where name="CDPUserSvc_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: Cloud Backup and Restore Service_a094e
sc query "CloudBackupRestoreSvc_a094e"
wmic service where name="CloudBackupRestoreSvc_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: ConsentUX User Service_a094e
sc query "ConsentUxUserSvc_a094e"
wmic service where name="ConsentUxUserSvc_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: CredentialEnrollmentManagerUserSvc_a094e
sc query "CredentialEnrollmentManagerUserSvc_a094e"
wmic service where name="CredentialEnrollmentManagerUserSvc_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: DeviceAssociationBroker_a094e
sc query "DeviceAssociationBrokerSvc_a094e"
wmic service where name="DeviceAssociationBrokerSvc_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: DevicePicker_a094e
sc query "DevicePickerUserSvc_a094e"
wmic service where name="DevicePickerUserSvc_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: DevicesFlow_a094e
sc query "DevicesFlowUserSvc_a094e"
wmic service where name="DevicesFlowUserSvc_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: MessagingService_a094e
sc query "MessagingService_a094e"
wmic service where name="MessagingService_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: Now Playing Session Manager Service_a094e
sc query "NPSMSvc_a094e"
wmic service where name="NPSMSvc_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: Sync Host_a094e
sc query "OneSyncSvc_a094e"
wmic service where name="OneSyncSvc_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: P9RdrService_a094e
sc query "P9RdrService_a094e"
wmic service where name="P9RdrService_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: PenService_a094e
sc query "PenService_a094e"
wmic service where name="PenService_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: Contact Data_a094e
sc query "PimIndexMaintenanceSvc_a094e"
wmic service where name="PimIndexMaintenanceSvc_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: PrintWorkflow_a094e
sc query "PrintWorkflowUserSvc_a094e"
wmic service where name="PrintWorkflowUserSvc_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: Udk User Service_a094e
sc query "UdkUserSvc_a094e"
wmic service where name="UdkUserSvc_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: User Data Storage_a094e
sc query "UnistoreSvc_a094e"
wmic service where name="UnistoreSvc_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: User Data Access_a094e
sc query "UserDataSvc_a094e"
wmic service where name="UserDataSvc_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: Web Threat Defense User Service_a094e
sc query "webthreatdefusersvc_a094e"
wmic service where name="webthreatdefusersvc_a094e" get *
Check file signature and location

REM INVESTIGATE suspicious service: Windows Push Notifications User Service_a094e
sc query "WpnUserService_a094e"
wmic service where name="WpnUserService_a094e" get *
Check file signature and location

echo Service security actions completed!
pause
