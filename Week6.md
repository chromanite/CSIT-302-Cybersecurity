# Week 6

## Table of Contents
---
1. [Vulnerability Management](#vulnerability-management) <br>
1.1 [Creating Vulnerability Management Strategy](#creating-vulnerability-management-strategy) <br>
1.2 [Vulnerability Management Tools](#vulnerability-management-tools) <br>
1.3 [Common Vulnerabilties and Exposure](#common-vulnerabilties-and-exposures)

<br>

2. [Implementing of Vulnerability Management](#implementation-of-vulnerability-management) <br>
2.1 [Implementing Vulnerability Management](#implementing-vulnerability-management) <br>
2.2 [Best practises for Vulnerability Management](#best-practises-for-vulnerability-management)

---

## Vulnerability Management

- ### Creating Vulnerability Management Strategy

    * Benefits of Vulnerability Management strategy
        1. Enable organisation to schedule all vulnerability mitigation process in an orderly way

        2. Targets and victims of cybersecurity incidents will be able to mitigate the damage that they have incurred or might incur

        3. Right counteractions are schedule to be performed at the right time to find and address vulnerabilities before attackers can abuse them

    <br>

    * **FIVE** distinct phases of Vulnerability Management strategy
        1. **CREATE ASSET INVENTORY**
            * Asset inventory is a list that security administratiors can use to go through devices an organisation has and highlight the ***ones that need to be covered by security software***

            * Small number of employee are responsible for managing the asset inventory, to ensure all devices are recorded and inventory remains up-to-date

            * Great tool that network and systems admin can use to quickly find and patch devices and systems

            <br>

            * ***CONSEQUENCE OF NOT HAVING PROPER INVENTORY***
                1. Devices may be left behind when new security software is being patched or installed

                2. The organisation may ***UNDERSPENDS or OVERSPENDS*** on security. This is because it cannot correctly determine the devices and systems that it needs to purchase protection for

            <br>

            * ***CHALLENGES***
                1. Poor change management
                
                2. Lack of effective tools for maintaining the inventory in a consistent manner

        <br>
        
        2. **PLANNING INFORMATION MANAGEMENT**
            * Plan ***how to control information flows*** into an organisation

            * Network security: Attention should be paid to this information flow to prevent threats from getting in or out of a network

            * Data security: Some organisation's data must never be accessed by attackers. E.g.: 
                
                * Information, such as trade secrets and PII of customers could cause irreparable damage if it is accessed by hackers

                * Organisation may lose its reputation and could also be fined huge sums of money for failing to protect user data.
            
            <br>

            * Computer Security Incident Response Team (CSIRT): In order to achieve **network and data security**, an organisation could deploy CSIRT team to handle any threats to its information storage and transmission

            * ***POLICY OF LEAST PRIVILEGE***: Policy ensures that users are denied access to all information apart from that which is necessary for them to perform their duties

            * End user devices: Measures should be put in place on end user devices to prevent illegal copying or reading of data

        <br>
            
        3. **PERFORMING RISK ASSESMENT (INCLUSIVE SUB-PHASES)**
            * Security team should do an in-depth analysis of the vulnerabilities that it faces

            * Organisation has to **prioritise some vulnerabilities over others** and allocate resouces to mitigate against them
            
            * Risk assessment comprised of ***SIX*** stages
                1. **SCOPE IDENTIFICATION**
                    * As organisation's security team has limited budget, it has to **IDENTIFY AREAS IT WILL COVER AND NOT COVER**
                    
                    * It determines what will be protected, its sensitivity and to what level it needs to be protected. The scope needs to be defined carefully since **IT WILL DETERMINE FROM WHERE INTERNAL AND EXTERNAL VULNERABILITY ANALYSIS WILL OCCUR**

                    <br>

                2. **COLLECTING DATA**
                    * Policies and procedures: Data needs to be collected about exisiting policies and procedures that are in place to safeguard the organisation from cyber threats

                    * Can be done through **Interviews, questionnaires, surveys
                    
                    * All networks, applications and systems that are covered in the scope should have relevant data collected. This data could include: Service pack, OS version, applications running, location, access control permissions, intrusion-detection tests, firewall tests, network surveys and port scans

                    <br>            

                3. **ANALYSIS OF POLICIES AND PROCEDURES**
                    * Important to review and analyse existing polices and procedure. Some policies may be inadequte or impractical

                    * While analysing policies and procedure, **one should determine their level of compliance** on the part of users and administrators. Punishments set for non-compliance should be analysed

                    * Outcomes: An organisation has sufficient policies and procedures to address vulnerabilities
                    
                    <br>

                4. **VULNERABILITY ANALYSIS**
                    * Vulnerabilties anaylsis involves identification of ***VULNERABLE ASSETS***
                    
                    * An analysis conducted to determine exposure of the organisation **(internal weakness)** to find out whether there are enough safeguards to protect itselfs

                    * The servers, printers, workstations, firewalls, routers, and switches on the organizational network are all targeted with these attacks. The aim is to simulate a real hacking scenario with the same tools and techniques that a potential attacker might use.

                    * Penetration testers need to **SIMULATE REAL ATTACKS** and find out the systems and devices that suffer stress and get compromised in the process

                    * False Positive: **BIGGEST SETBACK** in vulnerability analysis is the **NUMBER OF FALSE POSITIVES** that are identified that  needs to be filtered out

                    * Various tools have to be used together in order to come up with a reliable list of existing vulnerabilities in an organisation

                    * At end of this stage, identified vulnerabilities are graded according to the risk they post to the organisation
                        1. Minor class: vulnerabilities that requires lots of resources to exploit, yet have **VERY LITTLE IMPACT** on organisatoin

                        2. Moderate class: Vulnerabilities that have **MODERATE POTENTIAL FOR DAMAGE, EXPLOITABILITY AND EXPOSURE**

                        3. High-Severity class: Vulnerablities that require **FEWER RESOURCES TO EXPLOIT** but can do **LOTS OF DAMANGE TO AN ORGANISATION**

                    <br>

                5. **THREAT ANALYSIS**
                    * Analysis conducted to determine **EXTERNAL THREATS** to an organisation, which are **ACTIONS, CODE, OR SOFTWARE** that could lead to **TAMPERING, DESTRUCTION, OR INTERRUPTION OF DATA AND SERVICES** in an organisation

                    * Threats identified must be analyzed in order to determine their effects on an organisation

                    * Threats are graded in similar manner to vulnerabilities but are measured in terms of **MOTIVATION AND CAPABILITY**

                    * For instance, an insider may have **LOW MOTIVATION** to maliciously attack an organisation but could have lots of **CAPABILITY** to do so because of inside knowledge of working within the organisation

                    <br>

                6. **ANALYSIS OF ACCEPTABLE RISK**
                    * If existing policies, procedures and security mechanisms are **INADEQUATE**, it is assumed that there are risks in the organisation

                    * **CORRECTIVE ACTIONS** are taken to ensure that they are **UPDATED AND UPGRADED** until they are sufficient

                    * Once risks are addressed, other possible risk which is yet to be discovered is categorised as an **ACCEPTABLE RISK**
                        * However, other possible risk maybe more harmful over time, therefore they have to be analysed. Risk assesment ends only after risk is determined that they pose no threat. If they might pose a threat, safeguard standards are updated to address them
                
                <br>

            * Challenges in this phase
                1. Without an appropriate asset inventory, an organisation will not be able to indentify which device they should focus on

                2. Some scanners provide false assessment reports and guide the organisation down the wrong path

                3. Some scanning tools do not come with decent reporting features

                4. Disruption are another set of challenges that are experinced at this stage

        <br>

        4. **REPORTING AND REMEDIATION TRACKING**
            * **REPORT**:
                * Reporting helps system admins to understand the organisation's current state of security and gives something tangible to the management so that they can associate it with future direction of the organisation

                * Reporting comes before remediation, so that all information compiled in the vulnerability management phase can seamlessly flow to this phase

            <br>

            * **REMEDIATION**:
                * Remediation complements the premature ending of previous analyses of threat, vulnerability and acceptable risk by coming up with solutions to the shortcomings identified

                * All vulnerable hosts, servers and networking equipment are tracked down and necessary steps are established to remove the vulnerabilties and protect them from future exploits

                * Activities in this task include indentifying missing patches and checking for available upgrades to all systems in an organisation. Solutions are also identified for bugs that were picked up by scanning tools

                * If its well executed, vulnerability management is deemed to be successful

            * Challenges in this phase:
                * Report does not contain all required information may lead to poor remediation measures and thus leave the organisation exposed to threats

                * Lack of software documents to update software

                * Poor communication between software vendors and organisation when patching of system needs to be done

                * Lack of cooperation of the end users
                    * Remediation may introduce downtimes to end users, something users dont want to get
        
        <br>

        5. **RESPONSE PLANNING**
            * Process to execute the measures in regards to the risk

            * Response planning is important, without its execution, the organisation will still be exposed to threats
            
            * **SPEED OF EXECUTION IS MOST IMPORTANT** to consider in response planning
                * Large organisations face major hurdles when it comes to executing because of large numbers of devices that requires patches and upgrades

            * Examples
                1. Blaster worm: patch has been released 26 days before its propagation

                2. WannaCry

            <br>

            * Challenges in this phase:
                * Getting appropriate communications: When patch is released, hackers are never slow in finding ways to compromise the organisation that did not install patches

                <br>

                * Accountability: Organisation needs to know who to hold accountable for not installing patches
                    * Users may be responsible for **CANCELLING** installations. 
                    *It may be IT team that did not initiate patching process in time, there should always be an individual that can be held accountable for not installing patches
                
                <br>

                * Duplication of efforts: This normally occurs in large organisations when there are many IT security personnel
                    * They may use the same response plan, but due to poor communications, they may end up duplication each other's efforts while making very little progress

    
<br>        

---

- ### Vulnerability Management Tools

    * Asset Inventory Tools
        
        * Asset Inventory tools are aimed at recording computing assets that an organisation has, to ease their tracking when it comes to performing updates
        
        * Tools:
            * Peregrine tools
            * LANDesk Management Suit
            * StillSecure

    <br>

    * Information management tools

        * Information management tools are used to **DISSEMINATE INFORMATION ABOUT INTRUSION AND INTRUDERS** to the right people who can take reccomended actions

        * Number of tools that offer solutions to disseminate information in organisation through **EMAIL, WEBSITES AND DISTRIBUTION LISTS**. 
            * CERT Coordination Center
            * Security Focus
            * Symantec Security Response

        <br>

        * Mailing list can be set up so incident responders get alerts first, and once they verified security incident, rest of users can be informed
    
    <br>

    * Risk assesment tools

        * Most risk assesment tools are **DEVELOPED IN-HOUSE** since all organisations do not face same risk at the same time

        * There are many variations in risk management, thats why it might be tricky to use only one choice of software as universal tool to indentify and access risk that an organisation faces

        * In-house tools are **CHECKLISTS** developed by system and network administrators
            * Checklist should be made up of questions about potential vulnerabilities and threats that organisations are exposed to

            * Questions will be used by organisations to define risk levels of the vulnerabilities identified within its network

        <br>

        * Set of questions can be put on checklist:
            1. How can the **IDENTIFIED VULNERABILITES IMPACT** an organisation

            2. Which **BUSINESS RESOURCES** are at risk of being compromised?

            3. Is there a risk for **REMOTE EXPLOITATION**?

            4. What are the **CONSEQUENCES OF AN ATTACK**?

            5. Is the attack reliant on **TOOLS OR SCRIPTS**?

            6. How can the attack be **MITIGATED**?

        <br>

        * To complement checklist, organisations can acquire commercial tools that perform automated risk analysis such as **ARCSIGHT ENTERPRISE SECURITY MANAGER (ESM)**

    <br>

    * Vulnerability analysis tools

        * **TWO MOST COMMONLY USED VULNERABILITY SCANNER ARE**:
            1. **NESSUS**
            2. **NMAP**

        * Nmap can be used as basic vulnerability tool via nmap scripting enginge (NSE)

        * Nmap quickly maps new network and provides information about assets connected to it and their vulnerabilties

        * Nessus can perform an in-depth vulnerability assesment of the host connected to a network. The scanner will be able to determine their OS version, missing patches, and relevant exploits that can be used against the system. The tool also sorts vulnerabilities according to their threat levels

    <br>

    * Reporting and remediation tracking tools

        * There are many stakeholds in an organisation, not all can understand technical jargon. At the same time, IT department wants tool that can give them technical details without any alterations. Therefore the separation of audiences is important

        * Tools used in this stage:
            * Foundstone's Enterprise Manager 
            * Latis Reporting Tool

        * The tools have similar functionalities and provide **REPORTING FEATURES TAHT CAN BE CUSTOMISED TO DIFFERENT NEEDS OF USERS AND OTHER STAKEHOLDERS**

    <br>

    * Response planning tool 
        
        * **MOSTLY, RESPONSE PLANNING IS DONE THROUGH DOCUMENTATIONS!**

        * This step is where most resolution, eradication, cleansing and repair activities take place

        * Patches and system upgrades occur at this stage. There are not many commercial tools amde to faciliate this step

        * Documentaions help system and network administrators with patching and updating process for systems they are not familiar with

        * Documentations helps during changeovers where new staff are in charge of systems they never used before

        * Documentations help in emergency situations to avoid skipping some steps or making mistakes

    <br>
    
<br>        

---

- ### Common Vulnerabilties and Exposures

    * Common Vulnerabilties and Exposures (CVE)
        
        * Provides catalog for **PUBLICLY KNOWN INFORMATION SECURITY VULNERABILITIES AND EXPOSURES**

        * Supported by US-CERT, US Homeland Security Department and MITRE

        * Definitions given in CVE:
            * Vulnerability: State of being exposed to an attacker who can maliciously gain full access to network or system

            * Exposure: Mistake in software code or configuration that provides an attacker with indirect access to network or system

    <br>

    * Purpose of CVE:
        
        * Standardise the way each known vulnerability and/or exposure is identified: CVE database is maintained

        * Standard IDs provides security administrators with quick access to technical information about specific threat across multiple CVE-Compatible information sources

    <br>

    * Each entry in CVE Database consist of:
        1. CVE-ID: General syntax is CVE + YEAR + RANDOM NUMBER

        2. Description: Text description of issue

        3. References: URL and other information for issue

        4. Date Entry Created: Date entry was created

        5. Phase/Votes/Comments/Proposed: CVE DB can be searched by downloading master copy from http://cve.mitre.org/data/downloads/index.html

<br>

---

## Implementation of Vulnerability Management

- ### Implementing Vulnerability Management
    
    1. Creation of asset inventory
        * Serves as a register of ***ALL HOSTS IN A NETWORK*** and ***ALL SOFTWARE CONTAINED***

        * Organisation has to give certain IT staff member the task of keeping asset inventory updated

        * Asset inventory should at least show:
            1. Hardware and software assets owned by organisation and their ***RELEVANT LICENSE DETAILS***
            2. Vulnerabilities present in any of these assets

    <br>

    2. Facilitating information management
        * Setting up an ***EFFECTIVE WAY*** to get information about vulnerabilities and cybersecurity incidents to ***RELEVANT PEOPLE ASAP***

        * Tool capable of facilitating this stage requires the creation of ***MAILING LIST***
            * IR team members should be on mailing list to receive alerts

            * Other stakeholders of organisation should have access to this information once it has been confirmed

        * The tool provides periodic publications to users in an organisation to keep them updated about global cybersecurity incidents

    <br>

    3. Implementing risk assessment
        * Identification of the scope
        
        * Collection of data about existing policies and procedures that organisation has been using, and data about compliance should be collected
        
        * Existing policies and procedures should be analysed, to determine whether it is adequate in safeguarding security of organisation
        
        * Vulnarability and threat analysis should be performed, threats and vulnerabilities should be categorised according to severity
        
        * Organisation should define acceptable risk that it can face without experincing profound consequences

    <br>

    4. Implementing reporting and remediation tracking
        * All risks and vulnerabilities identified must be reported back to stakeholders of organisation
        
        * Report should be comprehensive and touch on all hardware and software assets belonging to organisation

        * Report should be fine-tuned to meet various audiences. From technical to non-technical information

        * After risks and vulnerabilities are identified, appropriate people to remedy should be stated

    <br>

    5. Implementing response planning
        * Confirms if preceding 5 steps were done right

        * Organisation should come up with means of ***PATCHING UPDATING UPGRADING*** systems that are identified with having risks or vulnerabilities

        * ***HIERARCHY OF SEVERITY*** identified in the risk and vulnerability assesment steps should be followed

<br>

---

<br>

- ### Best practises for Vulnerability Management

    * Asset Inventory
        * Organisation should establish a single point of authority. There should be one person or one group that can be held responsible if inventory is not up to date or has inconsistencies

        * Encourage the use of consistent abbreviations during data entry. It can be confusing to another person trying to go through the inventory if abbreviations keep changing

        * Inventory should be validated at least once a year

    <br>

    * Information management
        * Allowing employees to make conscious effort of subscribing to mailing list

        * Allow IR team to post it own reports, statics and advice on website for organisation's users

        * Organisation should also hold periodic conferences to discuss new vulnerabilities, virus, malicious activities and social engineering techniques with users

        * Organisation should have standardised template of how all security-related emails will look. Consistent look that is different from normal email format that users are used to

    <br>

    * Risk assesment
        * Review new vulnerabilities the moment they appear

        * Publish risk ratings to public or at least to organisation users

        * Ensure asset inventories are both available and updated at this stage so all host in network can be treated during risk assessment

        * Strict change management process so incoming staff are made aware of security posture of organisation and mechanisms in place to protect it

    <br>

    * Vulnerability analysis
        * Seek permission before extensively testing the network. This step might create serious disruptions to an organisation and do actual damage to host

        * Identify scanning tools that are best for its host. Some methods maybe overkill, other methods might be too shallow, unable to discover vulnerabilities

    <br>

    * Reporting and remidation tracking stage
        * Ensure there is reliable tool for sending reports to assets owners about vulnerabilties they have, and if vulnerabilities have been fixed

        * IR team should agree with management of remediation time frames and required resources, and make known the consequences of non-remeidiation

        * Remediation should be performed following the ***HIERARCHY OF SEVERITY***