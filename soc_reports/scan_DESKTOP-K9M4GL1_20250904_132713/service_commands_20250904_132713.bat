@echo off
REM Enhanced SOC Security Analyzer - Service Commands
REM Generated: 2025-09-04 13:27:13
REM Run as Administrator

echo ========================================
echo  SOC Security Analyzer Service Actions
echo ========================================

REM HIGH PRIORITY SERVICE ACTIONS
REM ENSURE DISABLED: NVIDIA LocalSystem Container
sc config "NvContainerLocalSystem" start= disabled

REM ENSURE DISABLED: NVIDIA Display Container LS
sc config "NVDisplay.ContainerLocalSystem" start= disabled

REM INVESTIGATE suspicious service: Wondershare WSID help
sc query "DFWSIDService"
wmic service where name="DFWSIDService" get *
Check file signature and location

REM INVESTIGATE suspicious service: COM+ Event System
sc query "EventSystem"
wmic service where name="EventSystem" get *
Check file signature and location

REM INVESTIGATE suspicious service: Local Session Manager
sc query "LSM"
wmic service where name="LSM" get *
Check file signature and location

REM INVESTIGATE suspicious service: Microsoft Defender Core Service
sc query "MDCoreSvc"
wmic service where name="MDCoreSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Network Setup Service
sc query "NetSetupSvc"
wmic service where name="NetSetupSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: NVIDIA NetworkService Container
sc query "NvContainerNetworkService"
wmic service where name="NvContainerNetworkService" get *
Check file signature and location

REM INVESTIGATE suspicious service: System Events Broker
sc query "SystemEventsBroker"
wmic service where name="SystemEventsBroker" get *
Check file signature and location

REM INVESTIGATE suspicious service: Diagnostic System Host
sc query "WdiSystemHost"
wmic service where name="WdiSystemHost" get *
Check file signature and location

REM INVESTIGATE suspicious service: Microsoft Defender Antivirus Network Inspection Service
sc query "WdNisSvc"
wmic service where name="WdNisSvc" get *
Check file signature and location

REM INVESTIGATE suspicious service: Microsoft Defender Antivirus Service
sc query "WinDefend"
wmic service where name="WinDefend" get *
Check file signature and location

echo Service security actions completed!
pause
