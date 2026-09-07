import { useEffect, useState } from "react";
import "./App.css";

const API = "http://127.0.0.1:8000";

function App() {
  const [page, setPage] = useState("login");

  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");

  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const [scanHistory, setScanHistory] = useState([]);

  const [networkData, setNetworkData] = useState({
    packet_count: "",
    connection_duration: "",
    failed_connections: "",
    bytes_sent: "",
    bytes_received: "",
    suspicious_port: "0"
  });

  const [networkResult, setNetworkResult] = useState(null);
  const [networkLoading, setNetworkLoading] = useState(false);

  const [logText, setLogText] = useState("");
  const [logResult, setLogResult] = useState(null);
  const [logLoading, setLogLoading] = useState(false);

  const [riskData, setRiskData] = useState({
    phishing_risk: 0,
    network_risk: 0,
    log_risk: 0
  });

  const [riskResult, setRiskResult] = useState(null);
  const [riskLoading, setRiskLoading] = useState(false);

  // ================= LOAD SCAN HISTORY =================

  const loadScanHistory = async () => {
    const savedToken = localStorage.getItem("token");

    if (!savedToken) {
      return;
    }

    try {
      const response = await fetch(`${API}/scan-history`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${savedToken}`
        }
      });

      const data = await response.json();

      if (!response.ok) {
        console.error("Could not load scan history:", data);
        return;
      }

      setScanHistory(data);
    } catch (error) {
      console.error("Error loading scan history:", error);
    }
  };

  // ================= LOAD DASHBOARD =================

  useEffect(() => {
    const savedToken = localStorage.getItem("token");

    if (savedToken) {
      setPage("dashboard");
      loadScanHistory();
    }
  }, []);

  // ================= REGISTER =================

  const register = async () => {
    if (!username || !email || !password) {
      alert("Please fill all fields");
      return;
    }

    try {
      const response = await fetch(
        `${API}/auth/register?username=${encodeURIComponent(
          username
        )}&email=${encodeURIComponent(
          email
        )}&password=${encodeURIComponent(password)}`,
        {
          method: "POST"
        }
      );

      const data = await response.json();

      if (!response.ok) {
        alert(data.detail || "Registration failed");
        return;
      }

      alert("Registration successful! Please login.");

      setUsername("");
      setEmail("");
      setPassword("");

      setPage("login");
    } catch (error) {
      alert("Backend is not running.");
    }
  };

  // ================= LOGIN =================

  const login = async () => {
    if (!loginUsername || !loginPassword) {
      alert("Please enter username and password");
      return;
    }

    try {
      const response = await fetch(
        `${API}/auth/login?username=${encodeURIComponent(
          loginUsername
        )}&password=${encodeURIComponent(loginPassword)}`,
        {
          method: "POST"
        }
      );

      const data = await response.json();

      if (!response.ok) {
        alert(data.detail || "Login failed");
        return;
      }

      localStorage.setItem("token", data.access_token);
      localStorage.setItem("username", data.username);

      setPage("dashboard");

      setLoginUsername("");
      setLoginPassword("");

      setTimeout(() => {
        loadScanHistory();
      }, 100);
    } catch (error) {
      alert("Backend is not running.");
    }
  };

  // ================= LOGOUT =================

  const logout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("username");

    setScanHistory([]);
    setResult(null);
    setNetworkResult(null);
    setLogResult(null);
    setLogText("");
    setRiskResult(null);

    setRiskData({
      phishing_risk: 0,
      network_risk: 0,
      log_risk: 0
    });

    setPage("login");
  };

  // ================= SAVE SCAN =================

  const saveScan = async (scanResult) => {
    const savedToken = localStorage.getItem("token");

    if (!savedToken) {
      console.error("No authentication token found.");
      return false;
    }

    try {
      const response = await fetch(
        `${API}/scan-history?url=${encodeURIComponent(
          scanResult.url
        )}&prediction=${encodeURIComponent(
          scanResult.prediction
        )}&risk_score=${Number(scanResult.risk_score)}`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${savedToken}`
          }
        }
      );

      const data = await response.json();

      if (!response.ok) {
        console.error("Failed to save scan:", data);
        return false;
      }

      console.log("Scan saved successfully:", data);

      await loadScanHistory();

      return true;
    } catch (error) {
      console.error("Error saving scan:", error);
      return false;
    }
  };

  // ================= NETWORK IDS =================

  const scanNetwork = async () => {
    if (
      networkData.packet_count === "" ||
      networkData.connection_duration === "" ||
      networkData.failed_connections === "" ||
      networkData.bytes_sent === "" ||
      networkData.bytes_received === ""
    ) {
      alert("Please fill all network fields");
      return;
    }

    setNetworkLoading(true);
    setNetworkResult(null);

    try {
      const response = await fetch(`${API}/detect/network`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          packet_count: Number(networkData.packet_count),
          connection_duration: Number(
            networkData.connection_duration
          ),
          failed_connections: Number(
            networkData.failed_connections
          ),
          bytes_sent: Number(networkData.bytes_sent),
          bytes_received: Number(networkData.bytes_received),
          suspicious_port: Number(
            networkData.suspicious_port
          )
        })
      });

      const data = await response.json();

      if (!response.ok) {
        alert(data.detail || "Network scan failed");
        setNetworkLoading(false);
        return;
      }

      setNetworkResult(data);

      setRiskData((previous) => ({
        ...previous,
        network_risk: data.risk_score
      }));

      await saveScan({
        url: "NETWORK ANALYSIS",
        prediction: data.prediction,
        risk_score: data.risk_score
      });
    } catch (error) {
      alert("Cannot connect to CyberShield backend.");
    }

    setNetworkLoading(false);
  };

  // ================= LOG ANALYZER =================

  const scanLog = async () => {
    if (!logText.trim()) {
      alert("Please enter a log message");
      return;
    }

    setLogLoading(true);
    setLogResult(null);

    try {
      const response = await fetch(`${API}/detect/log`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          log: logText
        })
      });

      const data = await response.json();

      if (!response.ok) {
        alert(data.detail || "Log analysis failed");
        setLogLoading(false);
        return;
      }

      setLogResult(data);

      setRiskData((previous) => ({
        ...previous,
        log_risk: data.risk_score
      }));

      await saveScan({
        url: "LOG ANALYSIS",
        prediction: data.prediction,
        risk_score: data.risk_score
      });
    } catch (error) {
      alert("Cannot connect to CyberShield backend.");
    }

    setLogLoading(false);
  };

  // ================= URL SCANNER =================

  const scanURL = async () => {
    if (!url.trim()) {
      alert("Please enter a URL");
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const response = await fetch(
        `${API}/detect/phishing-url`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            url: url
          })
        }
      );

      const data = await response.json();

      if (!response.ok) {
        alert(data.detail || "Scan failed");
        setLoading(false);
        return;
      }

      setResult(data);

      setRiskData((previous) => ({
        ...previous,
        phishing_risk: data.risk_score
      }));

      await saveScan(data);

      setUrl("");
    } catch (error) {
      alert("Cannot connect to CyberShield backend.");
    }

    setLoading(false);
  };

  // ================= RISK ENGINE =================

  const calculateRisk = async () => {
    setRiskLoading(true);
    setRiskResult(null);

    try {
      const response = await fetch(
        `${API}/risk/calculate`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            phishing_risk: Number(
              riskData.phishing_risk
            ),
            network_risk: Number(
              riskData.network_risk
            ),
            log_risk: Number(
              riskData.log_risk
            )
          })
        }
      );

      const data = await response.json();

      if (!response.ok) {
        alert(data.detail || "Risk calculation failed");
        setRiskLoading(false);
        return;
      }

      setRiskResult(data);
    } catch (error) {
      alert("Cannot connect to CyberShield backend.");
    }

    setRiskLoading(false);
  };

  // ================= STATISTICS =================

  const totalScans = scanHistory.length;

  const threatPredictions = [
    "PHISHING",
    "INTRUSION",
    "SUSPICIOUS",
    "HIGH RISK",
    "MEDIUM RISK"
  ];

  const safePredictions = [
    "SAFE",
    "NORMAL",
    "LOW RISK"
  ];

  const threatsDetected = scanHistory.filter(
    (scan) =>
      threatPredictions.includes(
        String(scan.prediction).toUpperCase()
      )
  ).length;

  const safeScans = scanHistory.filter(
    (scan) =>
      safePredictions.includes(
        String(scan.prediction).toUpperCase()
      )
  ).length;

  // ================= ANALYTICS =================

  const phishingCount = scanHistory.filter(
    (scan) =>
      String(scan.prediction).toUpperCase() ===
      "PHISHING"
  ).length;

  const intrusionCount = scanHistory.filter(
    (scan) =>
      String(scan.prediction).toUpperCase() ===
      "INTRUSION"
  ).length;

  const suspiciousCount = scanHistory.filter(
    (scan) =>
      String(scan.prediction).toUpperCase() ===
      "SUSPICIOUS"
  ).length;

  const highRiskCount = scanHistory.filter(
    (scan) =>
      String(scan.prediction).toUpperCase() ===
      "HIGH RISK"
  ).length;

  const mediumRiskCount = scanHistory.filter(
    (scan) =>
      String(scan.prediction).toUpperCase() ===
      "MEDIUM RISK"
  ).length;

  const threatPercentage =
    totalScans > 0
      ? ((threatsDetected / totalScans) * 100).toFixed(1)
      : 0;

  const safePercentage =
    totalScans > 0
      ? ((safeScans / totalScans) * 100).toFixed(1)
      : 0;

  const averageRisk =
    totalScans > 0
      ? (
          scanHistory.reduce(
            (sum, scan) =>
              sum + Number(scan.risk_score || 0),
            0
          ) / totalScans
        ).toFixed(1)
      : 0;

  // ================= THREAT COUNT SCALE =================

  const maxThreatCount = Math.max(
    phishingCount,
    intrusionCount,
    suspiciousCount,
    highRiskCount,
    mediumRiskCount,
    safeScans,
    1
  );

  const currentUser =
    localStorage.getItem("username") || "User";

  // ================= LOGIN =================

  if (page === "login") {
    return (
      <div className="auth-page">
        <div className="auth-card">

          <div className="logo">🛡️</div>

          <h1>CyberShield AI</h1>

          <p className="auth-subtitle">
            Multi-Threat Detection Platform
          </p>

          <h2>Welcome Back</h2>

          <input
            type="text"
            placeholder="Username"
            value={loginUsername}
            onChange={(e) =>
              setLoginUsername(e.target.value)
            }
          />

          <input
            type="password"
            placeholder="Password"
            value={loginPassword}
            onChange={(e) =>
              setLoginPassword(e.target.value)
            }
          />

          <button onClick={login}>
            Login
          </button>

          <p className="switch-text">
            Don't have an account?{" "}
            <span
              onClick={() =>
                setPage("register")
              }
            >
              Register
            </span>
          </p>

        </div>
      </div>
    );
  }

  // ================= REGISTER =================

  if (page === "register") {
    return (
      <div className="auth-page">
        <div className="auth-card">

          <div className="logo">🛡️</div>

          <h1>CyberShield AI</h1>

          <p className="auth-subtitle">
            Create your security account
          </p>

          <h2>Create Account</h2>

          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) =>
              setUsername(e.target.value)
            }
          />

          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) =>
              setEmail(e.target.value)
            }
          />

          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) =>
              setPassword(e.target.value)
            }
          />

          <button onClick={register}>
            Register
          </button>

          <p className="switch-text">
            Already have an account?{" "}
            <span
              onClick={() =>
                setPage("login")
              }
            >
              Login
            </span>
          </p>

        </div>
      </div>
    );
  }

  // ================= DASHBOARD =================

  return (
    <div className="app">

      {/* HEADER */}

      <header className="header">

        <div className="brand">

          <span className="brand-icon">
            🛡️
          </span>

          <div>
            <h2>CyberShield AI</h2>

            <small>
              Multi-Threat Detection Platform
            </small>
          </div>

        </div>

        <div className="header-right">

          <span className="status">
            <span className="status-dot"></span>
            System Online
          </span>

          <span className="user">
            👤 {currentUser}
          </span>

          <button
            className="logout-btn"
            onClick={logout}
          >
            Logout
          </button>

        </div>

      </header>

      <main className="dashboard">

        {/* HERO */}

        <section className="hero">

          <p className="eyebrow">
            AI-POWERED CYBERSECURITY
          </p>

          <h1>
            Security Overview
          </h1>

          <p>
            Monitor threats, analyze security
            activity, and evaluate your overall
            cybersecurity risk from one dashboard.
          </p>

        </section>

        {/* ================= STATISTICS ================= */}

        <section className="stats-grid">

          <div className="stat-card">

            <span className="stat-icon">
              🔍
            </span>

            <div>
              <p>Total Scans</p>

              <h2>{totalScans}</h2>

              <small>
                Security analyses performed
              </small>
            </div>

          </div>

          <div className="stat-card danger">

            <span className="stat-icon">
              🚨
            </span>

            <div>
              <p>Threats Detected</p>

              <h2>{threatsDetected}</h2>

              <small>
                Suspicious activities identified
              </small>
            </div>

          </div>

          <div className="stat-card safe">

            <span className="stat-icon">
              ✅
            </span>

            <div>
              <p>Safe Scans</p>

              <h2>{safeScans}</h2>

              <small>
                Safe or normal results
              </small>
            </div>

          </div>

        </section>

        {/* ================= SECURITY ANALYTICS ================= */}

        <section className="scanner-card analytics-card">

          <div className="section-title">

            <div>

              <span className="section-icon">
                📊
              </span>

              <div>

                <h2>
                  Security Analytics
                </h2>

                <p>
                  Real-time analysis of your security
                  scan activity and threat distribution.
                </p>

              </div>

            </div>

          </div>

          <div className="analytics-grid">

            <div className="analytics-box">
              <span>🎣</span>

              <div>
                <p>Phishing</p>
                <h3>{phishingCount}</h3>
              </div>
            </div>

            <div className="analytics-box">
              <span>🌐</span>

              <div>
                <p>Network Intrusions</p>
                <h3>{intrusionCount}</h3>
              </div>
            </div>

            <div className="analytics-box">
              <span>⚠️</span>

              <div>
                <p>Suspicious</p>
                <h3>{suspiciousCount}</h3>
              </div>
            </div>

            <div className="analytics-box">
              <span>🚨</span>

              <div>
                <p>High Risk</p>
                <h3>{highRiskCount}</h3>
              </div>
            </div>

          </div>

          <div className="analytics-summary">

            <div className="analytics-summary-item">

              <span>
                Threat Percentage
              </span>

              <strong>
                {threatPercentage}%
              </strong>

            </div>

            <div className="analytics-summary-item">

              <span>
                Safe Percentage
              </span>

              <strong>
                {safePercentage}%
              </strong>

            </div>

            <div className="analytics-summary-item">

              <span>
                Average Risk
              </span>

              <strong>
                {averageRisk}
              </strong>

            </div>

          </div>

          <div className="analytics-distribution">

            <div className="distribution-header">

              <h3>
                Threat Distribution
              </h3>

              <span>
                {totalScans} Total Scans
              </span>

            </div>

            <div className="distribution-bar">

              <div
                className="distribution-phishing"
                style={{
                  width: `${
                    totalScans > 0
                      ? (phishingCount / totalScans) * 100
                      : 0
                  }%`
                }}
              ></div>

              <div
                className="distribution-intrusion"
                style={{
                  width: `${
                    totalScans > 0
                      ? (intrusionCount / totalScans) * 100
                      : 0
                  }%`
                }}
              ></div>

              <div
                className="distribution-suspicious"
                style={{
                  width: `${
                    totalScans > 0
                      ? (suspiciousCount / totalScans) * 100
                      : 0
                  }%`
                }}
              ></div>

              <div
                className="distribution-high"
                style={{
                  width: `${
                    totalScans > 0
                      ? (highRiskCount / totalScans) * 100
                      : 0
                  }%`
                }}
              ></div>

              <div
                className="distribution-medium"
                style={{
                  width: `${
                    totalScans > 0
                      ? (mediumRiskCount / totalScans) * 100
                      : 0
                  }%`
                }}
              ></div>

              <div
                className="distribution-safe"
                style={{
                  width: `${
                    totalScans > 0
                      ? (safeScans / totalScans) * 100
                      : 0
                  }%`
                }}
              ></div>

            </div>

            <div className="distribution-legend">

              <span>
                <i className="legend-phishing"></i>
                Phishing
              </span>

              <span>
                <i className="legend-intrusion"></i>
                Intrusion
              </span>

              <span>
                <i className="legend-suspicious"></i>
                Suspicious
              </span>

              <span>
                <i className="legend-high"></i>
                High Risk
              </span>

              <span>
                <i className="legend-medium"></i>
                Medium Risk
              </span>

              <span>
                <i className="legend-safe"></i>
                Safe
              </span>

            </div>

          </div>

          {/* ================= THREAT COUNT OVERVIEW ================= */}

          <div className="threat-chart">

            <div className="distribution-header">

              <h3>
                Threat Count Overview
              </h3>

              <span>
                Based on scan history
              </span>

            </div>

            <div className="threat-chart-bars">

              <div className="chart-item">

                <span>
                  Phishing
                </span>

                <div className="chart-track">

                  <div
                    className="chart-fill phishing-fill"
                    style={{
                      width: `${
                        (phishingCount / maxThreatCount) * 100
                      }%`
                    }}
                  ></div>

                </div>

                <strong>
                  {phishingCount}
                </strong>

              </div>

              <div className="chart-item">

                <span>
                  Intrusion
                </span>

                <div className="chart-track">

                  <div
                    className="chart-fill intrusion-fill"
                    style={{
                      width: `${
                        (intrusionCount / maxThreatCount) * 100
                      }%`
                    }}
                  ></div>

                </div>

                <strong>
                  {intrusionCount}
                </strong>

              </div>

              <div className="chart-item">

                <span>
                  Suspicious
                </span>

                <div className="chart-track">

                  <div
                    className="chart-fill suspicious-fill"
                    style={{
                      width: `${
                        (suspiciousCount / maxThreatCount) * 100
                      }%`
                    }}
                  ></div>

                </div>

                <strong>
                  {suspiciousCount}
                </strong>

              </div>

              <div className="chart-item">

                <span>
                  High Risk
                </span>

                <div className="chart-track">

                  <div
                    className="chart-fill high-fill"
                    style={{
                      width: `${
                        (highRiskCount / maxThreatCount) * 100
                      }%`
                    }}
                  ></div>

                </div>

                <strong>
                  {highRiskCount}
                </strong>

              </div>

              <div className="chart-item">

                <span>
                  Medium Risk
                </span>

                <div className="chart-track">

                  <div
                    className="chart-fill medium-fill"
                    style={{
                      width: `${
                        (mediumRiskCount / maxThreatCount) * 100
                      }%`
                    }}
                  ></div>

                </div>

                <strong>
                  {mediumRiskCount}
                </strong>

              </div>

              <div className="chart-item">

                <span>
                  Safe
                </span>

                <div className="chart-track">

                  <div
                    className="chart-fill safe-fill"
                    style={{
                      width: `${
                        (safeScans / maxThreatCount) * 100
                      }%`
                    }}
                  ></div>

                </div>

                <strong>
                  {safeScans}
                </strong>

              </div>

            </div>

          </div>

        </section>

        {/* ================= SECURITY STATUS ================= */}

        <section className="scanner-card">

          <div className="section-title">

            <div>

              <span className="section-icon">
                🛡️
              </span>

              <div>

                <h2>
                  Security Monitoring Status
                </h2>

                <p>
                  CyberShield AI monitoring modules
                  are ready for security analysis.
                </p>

              </div>

            </div>

          </div>

          <div className="features-grid">

            <div className="feature-card">
              <span>🎣</span>
              <h3>Phishing</h3>
              <p>
                URL security analysis
              </p>
            </div>

            <div className="feature-card">
              <span>🌐</span>
              <h3>Network IDS</h3>
              <p>
                Intrusion monitoring
              </p>
            </div>

            <div className="feature-card">
              <span>📋</span>
              <h3>Log Analyzer</h3>
              <p>
                Security event analysis
              </p>
            </div>

            <div className="feature-card">
              <span>🤖</span>
              <h3>Risk Engine</h3>
              <p>
                Overall risk calculation
              </p>
            </div>

          </div>

        </section>

        {/* ================= URL SCANNER ================= */}

        <section className="scanner-card">

          <div className="section-title">

            <div>

              <span className="section-icon">
                🔎
              </span>

              <div>

                <h2>
                  URL Security Scanner
                </h2>

                <p>
                  Enter a URL to check for
                  potential phishing indicators.
                </p>

              </div>

            </div>

          </div>

          <div className="scanner-input">

            <input
              type="text"
              placeholder="https://example.com"
              value={url}
              onChange={(e) =>
                setUrl(e.target.value)
              }
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  scanURL();
                }
              }}
            />

            <button
              onClick={scanURL}
              disabled={loading}
            >
              {loading
                ? "Analyzing..."
                : "Analyze URL"}
            </button>

          </div>

        </section>

        {/* ================= NETWORK IDS ================= */}

        <section className="scanner-card">

          <div className="section-title">

            <div>

              <span className="section-icon">
                🌐
              </span>

              <div>

                <h2>
                  Network Intrusion Detection
                </h2>

                <p>
                  Analyze network activity for
                  potential intrusion indicators.
                </p>

              </div>

            </div>

          </div>

          <div className="network-form">

            <input
              type="number"
              placeholder="Packet Count"
              value={networkData.packet_count}
              onChange={(e) =>
                setNetworkData({
                  ...networkData,
                  packet_count:
                    e.target.value
                })
              }
            />

            <input
              type="number"
              placeholder="Connection Duration"
              value={
                networkData.connection_duration
              }
              onChange={(e) =>
                setNetworkData({
                  ...networkData,
                  connection_duration:
                    e.target.value
                })
              }
            />

            <input
              type="number"
              placeholder="Failed Connections"
              value={
                networkData.failed_connections
              }
              onChange={(e) =>
                setNetworkData({
                  ...networkData,
                  failed_connections:
                    e.target.value
                })
              }
            />

            <input
              type="number"
              placeholder="Bytes Sent"
              value={networkData.bytes_sent}
              onChange={(e) =>
                setNetworkData({
                  ...networkData,
                  bytes_sent:
                    e.target.value
                })
              }
            />

            <input
              type="number"
              placeholder="Bytes Received"
              value={
                networkData.bytes_received
              }
              onChange={(e) =>
                setNetworkData({
                  ...networkData,
                  bytes_received:
                    e.target.value
                })
              }
            />

            <select
              value={
                networkData.suspicious_port
              }
              onChange={(e) =>
                setNetworkData({
                  ...networkData,
                  suspicious_port:
                    e.target.value
                })
              }
            >
              <option value="0">
                Normal Port
              </option>

              <option value="1">
                Suspicious Port
              </option>
            </select>

          </div>

          <button
            onClick={scanNetwork}
            disabled={networkLoading}
          >
            {networkLoading
              ? "Analyzing Network..."
              : "Analyze Network"}
          </button>

        </section>

        {/* ================= NETWORK RESULT ================= */}

        {networkResult && (

          <section className="result-card">

            <div className="result-header">

              <div>

                <p className="eyebrow">
                  NETWORK ANALYSIS RESULT
                </p>

                <h2>
                  {networkResult.prediction}
                </h2>

                <p className="scanned-url">
                  Network activity analysis
                  completed
                </p>

              </div>

              <div className="risk-score">

                <span>
                  Risk Score
                </span>

                <strong>
                  {networkResult.risk_score}
                </strong>

                <small>/ 100</small>

              </div>

            </div>

            <div className="risk-bar">

              <div
                style={{
                  width: `${networkResult.risk_score}%`
                }}
              ></div>

            </div>

            <div className="findings">

              <h3>
                🌐 Network Features
              </h3>

              <div className="finding">
                <span>•</span>
                Packet Count:{" "}
                {networkResult.features.packet_count}
              </div>

              <div className="finding">
                <span>•</span>
                Connection Duration:{" "}
                {
                  networkResult.features
                    .connection_duration
                }
              </div>

              <div className="finding">
                <span>•</span>
                Failed Connections:{" "}
                {
                  networkResult.features
                    .failed_connections
                }
              </div>

              <div className="finding">
                <span>•</span>
                Bytes Sent:{" "}
                {networkResult.features.bytes_sent}
              </div>

              <div className="finding">
                <span>•</span>
                Bytes Received:{" "}
                {
                  networkResult.features
                    .bytes_received
                }
              </div>

              <div className="finding">
                <span>•</span>
                Suspicious Port:{" "}
                {
                  networkResult.features
                    .suspicious_port === 1
                    ? "Yes"
                    : "No"
                }
              </div>

              <div className="finding">
                <span>•</span>
                Model Confidence:{" "}
                {networkResult.confidence}%
              </div>

            </div>

          </section>

        )}

        {/* ================= LOG ANALYZER ================= */}

        <section className="scanner-card">

          <div className="section-title">

            <div>

              <span className="section-icon">
                📋
              </span>

              <div>

                <h2>
                  Log Threat Analyzer
                </h2>

                <p>
                  Analyze security logs and identify
                  suspicious activities.
                </p>

              </div>

            </div>

          </div>

          <textarea
            className="log-textarea"
            placeholder="Paste a security log here..."
            value={logText}
            onChange={(e) =>
              setLogText(e.target.value)
            }
            rows="7"
          ></textarea>

          <button
            onClick={scanLog}
            disabled={logLoading}
          >
            {logLoading
              ? "Analyzing Log..."
              : "Analyze Security Log"}
          </button>

        </section>

        {/* ================= LOG RESULT ================= */}

        {logResult && (

          <section className="result-card">

            <div className="result-header">

              <div>

                <p className="eyebrow">
                  LOG THREAT ANALYSIS RESULT
                </p>

                <h2>
                  {logResult.prediction}
                </h2>

                <p className="scanned-url">
                  Security log analysis completed
                </p>

              </div>

              <div className="risk-score">

                <span>
                  Risk Score
                </span>

                <strong>
                  {logResult.risk_score}
                </strong>

                <small>/ 100</small>

              </div>

            </div>

            <div className="risk-bar">

              <div
                style={{
                  width: `${logResult.risk_score}%`
                }}
              ></div>

            </div>

            <div className="findings">

              <h3>
                ⚠️ Security Findings
              </h3>

              {logResult.threats &&
              logResult.threats.length > 0 ? (

                logResult.threats.map(
                  (threat, index) => (

                    <div
                      className="finding"
                      key={index}
                    >

                      <span>!</span>

                      {threat}

                    </div>
                  )
                )

              ) : (

                <div className="safe-message">
                  ✅ No suspicious indicators
                  detected.
                </div>

              )}

            </div>

          </section>

        )}

        {/* ================= RISK ENGINE ================= */}

        <section className="scanner-card">

          <div className="section-title">

            <div>

              <span className="section-icon">
                🤖
              </span>

              <div>

                <h2>
                  AI Risk Engine
                </h2>

                <p>
                  Combine phishing, network, and
                  log risk scores to calculate
                  overall security risk.
                </p>

              </div>

            </div>

          </div>

          <div className="risk-input-grid">

            <div className="risk-input-card">

              <label>
                🎣 Phishing Risk
              </label>

              <input
                type="number"
                min="0"
                max="100"
                value={riskData.phishing_risk}
                onChange={(e) =>
                  setRiskData({
                    ...riskData,
                    phishing_risk:
                      e.target.value
                  })
                }
              />

              <small>0 - 100</small>

            </div>

            <div className="risk-input-card">

              <label>
                🌐 Network Risk
              </label>

              <input
                type="number"
                min="0"
                max="100"
                value={riskData.network_risk}
                onChange={(e) =>
                  setRiskData({
                    ...riskData,
                    network_risk:
                      e.target.value
                  })
                }
              />

              <small>0 - 100</small>

            </div>

            <div className="risk-input-card">

              <label>
                📋 Log Risk
              </label>

              <input
                type="number"
                min="0"
                max="100"
                value={riskData.log_risk}
                onChange={(e) =>
                  setRiskData({
                    ...riskData,
                    log_risk:
                      e.target.value
                  })
                }
              />

              <small>0 - 100</small>

            </div>

          </div>

          <button
            onClick={calculateRisk}
            disabled={riskLoading}
          >
            {riskLoading
              ? "Calculating Risk..."
              : "Calculate Overall Risk"}
          </button>

        </section>

        {/* ================= RISK RESULT ================= */}

        {riskResult && (

          <section className="result-card">

            <div className="result-header">

              <div>

                <p className="eyebrow">
                  AI RISK ENGINE RESULT
                </p>

                <h2>
                  {riskResult.risk_level}
                </h2>

                <p className="scanned-url">
                  Overall security risk calculated
                </p>

              </div>

              <div className="risk-score">

                <span>
                  Overall Risk
                </span>

                <strong>
                  {riskResult.overall_risk}
                </strong>

                <small>/ 100</small>

              </div>

            </div>

            <div className="risk-bar">

              <div
                style={{
                  width: `${riskResult.overall_risk}%`
                }}
              ></div>

            </div>

            <div className="findings">

              <h3>
                🛡️ Risk Breakdown
              </h3>

              <div className="finding">
                <span>🎣</span>
                Phishing Risk:{" "}
                {riskResult.phishing_risk}
              </div>

              <div className="finding">
                <span>🌐</span>
                Network Risk:{" "}
                {riskResult.network_risk}
              </div>

              <div className="finding">
                <span>📋</span>
                Log Risk:{" "}
                {riskResult.log_risk}
              </div>

              <div className="finding">
                <span>🤖</span>
                Overall Risk:{" "}
                {riskResult.overall_risk}
              </div>

              <div className="finding">
                <span>⚠️</span>
                Risk Level:{" "}
                {riskResult.risk_level}
              </div>

            </div>

          </section>

        )}

        {/* ================= URL RESULT ================= */}

        {result && (

          <section className="result-card">

            <div className="result-header">

              <div>

                <p className="eyebrow">
                  ANALYSIS RESULT
                </p>

                <h2>
                  {result.prediction}
                </h2>

                <p className="scanned-url">
                  {result.url}
                </p>

              </div>

              <div className="risk-score">

                <span>
                  Risk Score
                </span>

                <strong>
                  {result.risk_score}
                </strong>

                <small>/ 100</small>

              </div>

            </div>

            <div className="risk-bar">

              <div
                style={{
                  width: `${result.risk_score}%`
                }}
              ></div>

            </div>

            {result.warnings &&
            result.warnings.length > 0 && (

              <div className="findings">

                <h3>
                  ⚠️ Security Findings
                </h3>

                {result.warnings.map(
                  (warning, index) => (

                    <div
                      className="finding"
                      key={index}
                    >

                      <span>!</span>

                      {warning}

                    </div>
                  )
                )}

              </div>

            )}

            {result.warnings &&
            result.warnings.length === 0 && (

              <div className="safe-message">
                ✅ No suspicious indicators
                detected.
              </div>

            )}

          </section>

        )}

        {/* ================= SCAN HISTORY ================= */}

        <section className="history-card">

          <div className="history-header">

            <div>

              <p className="eyebrow">
                DATABASE RECORDS
              </p>

              <h2>
                Scan History
              </h2>

              <p>
                Recent security analyses stored
                in PostgreSQL.
              </p>

            </div>

            <span className="history-count">
              {scanHistory.length} scans
            </span>

          </div>

          {scanHistory.length === 0 ? (

            <div className="empty-history">

              <span>📋</span>

              <p>
                No scans performed yet.
              </p>

            </div>

          ) : (

            <div className="history-list">

              {scanHistory.map(
                (scan) => {

                  const prediction =
                    String(
                      scan.prediction
                    ).toUpperCase();

                  const isDanger =
                    prediction === "PHISHING" ||
                    prediction === "INTRUSION" ||
                    prediction === "HIGH RISK";

                  const isWarning =
                    prediction === "SUSPICIOUS" ||
                    prediction === "MEDIUM RISK";

                  return (
                    <div
                      className="history-item"
                      key={scan.id}
                    >

                      <div className="history-main">

                        <strong>
                          {scan.url}
                        </strong>

                        <small>
                          {scan.scanned_at
                            ? new Date(
                                scan.scanned_at
                              ).toLocaleString()
                            : "Recently scanned"}
                        </small>

                      </div>

                      <div className="history-result">

                        <span
                          className={
                            isDanger
                              ? "badge danger-badge"
                              : isWarning
                              ? "badge warning-badge"
                              : "badge safe-badge"
                          }
                        >
                          {scan.prediction}
                        </span>

                        <strong>
                          Risk: {scan.risk_score}
                        </strong>

                      </div>

                    </div>
                  );
                }
              )}

            </div>

          )}

        </section>

        {/* ================= FEATURES ================= */}

        <section className="features-section">

          <p className="eyebrow">
            SECURITY CAPABILITIES
          </p>

          <h2>
            CyberShield Protection
          </h2>

          <p className="features-description">
            A unified defensive cybersecurity
            platform combining multiple detection
            and risk-analysis capabilities.
          </p>

          <div className="features-grid">

            <div className="feature-card">

              <span>🎣</span>

              <h3>
                Phishing Detection
              </h3>

              <p>
                Detect suspicious URLs and
                phishing indicators using
                security analysis.
              </p>

            </div>

            <div className="feature-card">

              <span>🌐</span>

              <h3>
                Network Intrusion Detection
              </h3>

              <p>
                Analyze network activity and
                identify potential intrusion
                patterns.
              </p>

            </div>

            <div className="feature-card">

              <span>📋</span>

              <h3>
                Log Threat Analyzer
              </h3>

              <p>
                Analyze security logs and detect
                suspicious authentication,
                malware, network, and injection
                indicators.
              </p>

            </div>

            <div className="feature-card">

              <span>🤖</span>

              <h3>
                AI Risk Analysis
              </h3>

              <p>
                Combine multiple security signals
                to calculate an overall risk level.
              </p>

            </div>

            <div className="feature-card">

              <span>🗄️</span>

              <h3>
                Secure History
              </h3>

              <p>
                Store scan results securely in
                PostgreSQL for future analysis.
              </p>

            </div>

          </div>

        </section>

      </main>

      <footer>

        <p>
          CyberShield AI © 2026 · Defensive
          Cybersecurity Platform
        </p>

      </footer>

    </div>
  );
}

export default App;