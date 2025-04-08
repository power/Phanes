# 🚀 Phanes  

Phanes is an educational tool designed to help individuals enhance their **Active Directory knowledge**. The tool intends to do this by generating a realistic & random network in real-time with common AD misconfigurations. 

## 🔥 Key Vulnerabilities  
Phanes simulates networks with the following common **Active Directory security weaknesses**:  

- 🛠 **NTLM Relay**  
- 🔄 **DCSync Attacks**  
- 🔑 **Secrets Dump**  
- ❌ **Weak Access Controls**  
- 🎭 **Kerberoasting**  
- 🎭 **Unconstrained Delegation**  
- 🔥 **ASREP Roasting**  
- 🔓 **Weak Password Policies**  

## 📜 Additional Features  
Phanes goes beyond just simulating vulnerabilities, it **generates a detailed report** outlining:  

✅ The **identified vulnerabilities**  
✅ **Step-by-step guidance** on finding and exploiting them  
✅ **Security insights** to improve defenses  

## ⚙️ Default Usage  

To get started with Phanes, first launch PowerShell with execution policy bypassed:

```powershell
powershell -ep bypass
```
Then, run the script with the default parameters:
```
.\phanes.ps1 -dcip:"IP" -flags:"FLAGS" -Path:"PATH_TO_FILES"
```
### 🧾 Parameters

- **`-dcip`**: IP address of the Domain Controller  
- **`-flags`**: Custom execution flags (see below)  
- **`-Path`**: Output directory for reports and artifacts  

## 🏴 Available Flags  

When using the `-flags` argument, please use **one** of the following:

| **Flag**   | **Description**                                                       |
|------------|------------------------------------------------------------------------|
| `-All`     | Generates the network with **all** features of Phanes                  |
| `-Users`   | Adds 20 users to the environment, with **no vulnerabilities**          |
| `-DC`      | Adds vulnerabilities **only** to the `DC01` domain controller          |
| `-COMP`    | Adds vulnerabilities **only** to the `COMP01` workstation              |

## 💡 Example Usage

**.\phanes.ps1 -dcip:"192.168.18.149" -flags:"-DC:$true" -Path:".\"**
