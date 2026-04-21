# 🛡️ NetGuard IDS — Real-Time Network Intrusion Detection System

A full-stack cybersecurity application that monitors network traffic in real time,
detects 15 threat signatures, and visualises attacks on a live operator dashboard.

## 🚀 Features
- Real-time packet streaming via WebSocket
- 15 threat signatures — SYN Flood, SQL Injection, ARP Spoofing, C2 Beacon, Brute Force SSH, and more
- Deep packet inspection (headers, flags, TTL, payload)
- Geographic attack origin tracker
- Port scanner (Open / Closed / Filtered)
- IP blocking engine
- REST API with 6 endpoints

## 🛠️ Tech Stack
| Layer | Technology |
|---|---|
| Backend | Python 3.10+, FastAPI, Uvicorn |
| Real-time | WebSocket (RFC 6455) |
| Frontend | HTML5, CSS3, JavaScript |
| API | REST (6 endpoints) |

## ⚙️ Setup & Installation

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/netguard-ids.git
cd netguard-ids
```

### 2. Install backend dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 3. Start the backend server
```bash
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Open the dashboard
Open `frontend/index.html` in your browser.
The dashboard connects automatically to the backend via WebSocket.

## 📡 API Endpoints
| Method | Endpoint | Description |
|---|---|---|
| GET | /api/stats | System statistics |
| GET | /api/alerts | Recent alerts |
| GET | /api/packets | Captured packets |
| GET | /api/portscan | Port scan results |
| POST | /api/simulate-attack | Inject test attack |
| DELETE | /api/alerts | Clear all alerts |
| WS | /ws | Live packet stream |

## 🎓 Academic Context
- **University:** COER University, Roorkee
- **Department:** AI&ML and Cyber Security
- **Degree:** B.Tech Cyber Security
- **Session:** 2025–2026