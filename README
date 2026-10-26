🛡️ Edge Zero Trust Identity Broker (Prototype v1)
1. Executive Summary
This project implements a Zero Trust Architecture (ZTA) using a Software-Defined Perimeter (SDP). It replaces the traditional "Castle-and-Moat" security model (VPNs) with an Identity-Aware Proxy.

The system consists of two decoupled microservices:

The Policy Enforcement Point (Gateway): A "Traffic Cop" that intercepts all requests, verifies identity (JWT) and context (Device/Time), and enforces Role-Based Access Control (RBAC).

The Protected Resource (Internal Dashboard): A "Hidden" application listening on localhost that is invisible to the network and trusts only the Gateway.


2. Installation & Setup
Prerequisites
Python 3.9 or higher.

A terminal (PowerShell, CMD, or Bash).

Step 1: Install Dependencies
Navigate to the root folder (where requirements.txt is located) and run:
pip install -r requirements.txt


Step 2: Generate Security Certificates
(Only required if the gateway/certs/ folder is empty).
run: 
cd gateway
python make_certs.py
cd ..


3. Startup Instructions
You must run two separate terminals to simulate the architecture.

Terminal 1: The Protected Resource (Dashboard)
This represents the internal server we are hiding from the internet.
run:
cd dashboard
python dashboard_app.py
Status: Listening on http://127.0.0.1:3000.

Note: Do not access this URL directly (that is the "Attack" scenario).

Terminal 2: The Zero Trust Gateway
This is the only entry point allowed for users.
run:
cd gateway
python main.py
Status: Listening on https://0.0.0.0:8000.


4. How to Demo (The Script)
Open your browser (Chrome or Edge) and navigate to: 👉 https://localhost:8000/

(Accept the "Not Secure" self-signed certificate warning by clicking Advanced -> Proceed).

Scenario A: The "Admin" (Full Trust)
Login: Username admin / Password admin123

Observation: You are redirected to the Dashboard. You see a Blue Admin Box and "Delete" buttons.

Action: Add a new "Secret Note". It appears instantly.

Narrative: "The Gateway verified my identity and high-privilege role, granting full read/write access."

Scenario B: The "Viewer" (Least Privilege)
Action: Click Log Out (or open an Incognito window).

Login: Username viewer / Password viewer123

Observation: You see the Dashboard, but the Admin box and Delete buttons are GONE.

Narrative: "The Gateway injected a restricted role header. The application adapted its UI to prevent unauthorized actions."

Scenario C: The "Direct Attack" (Zero Trust Validation)
Action: Try to visit http://localhost:3000/ directly in the browser.

Observation: You either see a "Guest" view or are blocked entirely.

Narrative: "Bypassing the Gateway fails because the application requires the cryptographic headers that only the Gateway can provide."


(Just recommendations... if you have other ideas, please go with it,
anything to improve it is good)
5. Roadmap: What Needs to Be Done Next
To move this from "Prototype" to "Production-Ready," the following steps are required:

Phase 1: Advanced Policy Engine (Immediate)
Context-Aware Access: Update policies.py to block access based on:

Time of Day: Reject logins outside business hours (e.g., 9 AM - 5 PM).

Device Health: Block specific browsers (User-Agents) known to be insecure.

Audit Logging: Ensure access_audit.log captures all ALLOW and DENY decisions for forensics.

Phase 2: Edge Deployment
Hardware: Deploy the code to a Raspberry Pi 4.

Network Hardening: Configure the Pi's firewall (ufw) to drop all traffic to port 3000 from external IPs, ensuring the Gateway (port 8000) is the only physical way in.

Phase 3: Scalability
State Management: Implement Redis to store active session tokens. This allows for immediate "Kill Switch" functionality (revoking a compromised user instantly).


6. Recommendations to Impress Professors
Show the "Red" Screen (Live Policy Change):

During the demo, modify policies.py to block the "Admin" user (or block a specific browser like Firefox).

Show that even with the correct password, the system says "403 Forbidden: Policy Violation". This proves it's not just a login form—it's a smart security broker.

Visualize the "Invisible" Network:

Draw a diagram on the whiteboard showing the "Wall" around the Dashboard. Explain that in a real deployment, the Dashboard has no public IP address. It is "Dark" to the internet.

The "Audit Trail" Argument:

Open the access_audit.log file during the presentation.

Say: "In a breach, we don't just guess what happened. We have a timestamped cryptographic log of every single access attempt."

Hardware Efficiency:

Emphasize that this entire Zero Trust architecture runs on a standard Raspberry Pi using lightweight Python (FastAPI), proving that high-security infrastructure doesn't require expensive enterprise hardware.