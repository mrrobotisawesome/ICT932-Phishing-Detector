# ICT932 - Phishing Detector (PhishGuard)

**PhishGuard** is a web-based tool designed to help users analyze emails for potential phishing threats.  
Developed as a project for **ICT932 – Cybersecurity Testing and Assurance**, it is built with a strong focus on security, following the **DevSecOps** methodology.

---

##  Key Features

- **User Authentication:** Secure user registration and login system.  
- **Two-Factor Authentication (2FA):** Enhanced account security using TOTP (e.g., Google Authenticator).  
- **Role-Based Access Control (RBAC):** Separate access levels for regular users and admins.  
- **Email Analysis Engine:** A heuristic engine that scans email content for common phishing indicators such as suspicious links and urgent keywords.  
- **Clear Risk Assessment:** Provides a clear risk level — *Safe*, *Suspicious*, or *Malicious* — along with a detailed list of findings.  
- **Admin Dashboard:** An administrative interface for viewing all analyses performed on the system.

---

##  Technology Stack

| Component | Technology |
|------------|-------------|
| **Backend** | Python (Flask Framework) |
| **Frontend** | HTML, CSS, Bootstrap 5 |
| **Database** | SQLite (SQLAlchemy ORM) |
| **Security Libraries** | Flask-Bcrypt (Password Hashing), PyOTP (2FA Token Generation) |

---

##  Methodology

PhishGuard follows the **DevSecOps** approach — integrating security at every stage of development to ensure reliability, confidentiality, and integrity of user data.

---

**Project Course:** ICT932 – *Cybersecurity Testing and Assurance*  
**Project Name:** *PhishGuard – Email Phishing Detection Tool*
