import React, { useState } from "react";

export default function App() {
  const [xmlContent, setXmlContent] = useState("");
  const [nmapContent, setNmapContent] = useState("");
  const [liveInput, setLiveInput] = useState("");
  const [scanResults, setScanResults] = useState({});
  const [filter, setFilter] = useState("");

  const parseXml = (text) => {
    const parser = new DOMParser();
    const xml = parser.parseFromString(text, "text/xml");
    const hosts = Array.from(xml.getElementsByTagName("host"));
    const results = hosts.map((host) => {
      const address = host.getElementsByTagName("address")[0]?.getAttribute("addr") || "Unknown";
      const ports = Array.from(host.getElementsByTagName("port")).map((port) => {
        const portId = port.getAttribute("portid");
        const protocol = port.getAttribute("protocol");
        const state = port.getElementsByTagName("state")[0]?.getAttribute("state");
        const service = port.getElementsByTagName("service")[0]?.getAttribute("name") || "Unknown";
        const script = port.getElementsByTagName("script")[0]?.getAttribute("output") || "";
        return { portId, protocol, state, service, script };
      });
      return { address, ports };
    });
    setScanResults((prev) => ({ ...prev, xmlResults: results }));
  };

  const parseNmap = (text) => {
    const lines = text.split("\n");
    let results = [];
    let currentHost = null;

    lines.forEach((line) => {
      const hostMatch = line.match(/^Nmap scan report for (.+)/);
      if (hostMatch) {
        if (currentHost) results.push(currentHost);
        currentHost = { address: hostMatch[1], ports: [] };
      }
      const portMatch = line.match(/(\d+\/\w+)\s+(open)\s+(\S+)/);
      if (portMatch && currentHost) {
        currentHost.ports.push({ portId: portMatch[1], state: portMatch[2], service: portMatch[3] });
      }
    });
    if (currentHost) results.push(currentHost);
    setScanResults((prev) => ({ ...prev, grepResults: results }));
  };

  const handleFileUpload = (e, type) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target.result;
      if (type === "xml") {
        setXmlContent(text);
        parseXml(text);
      } else {
        setNmapContent(text);
        parseNmap(text);
      }
    };
    reader.readAsText(file);
  };

  const handleLivePaste = () => {
    parseNmap(liveInput);
  };

  const exportToJson = () => {
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const dataStr = JSON.stringify(scanResults, null, 2);
    const blob = new Blob([dataStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `nmap_results_${timestamp}.json`;
    a.click();
  };

  const exportToCSV = () => {
    const rows = [["Host", "Port", "Protocol", "State", "Service", "Script"]];

    (scanResults.xmlResults || []).forEach((host) => {
      host.ports.forEach((port) => {
        rows.push([
          host.address,
          port.portId,
          port.protocol,
          port.state,
          port.service,
          port.script.replace(/\n/g, " ")
        ]);
      });
    });

    (scanResults.grepResults || []).forEach((host) => {
      host.ports.forEach((port) => {
        rows.push([
          host.address,
          port.portId,
          "-",
          port.state,
          port.service,
          "-"
        ]);
      });
    });

    const csvContent = rows.map((e) => e.map((x) => `"${x}"`).join(",")).join("\n");
    const blob = new Blob([csvContent], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    a.href = url;
    a.download = `nmap_results_${timestamp}.csv`;
    a.click();
  };

  const filterPortData = (results) => {
    if (!filter) return results;
    return results
      .map((host) => ({
        ...host,
        ports: host.ports.filter(
          (port) =>
            port.state === "open" &&
            (port.service?.toLowerCase().includes(filter.toLowerCase()) ||
              port.portId?.includes(filter))
        )
      }))
      .filter((host) => host.ports.length > 0);
  };

  return (
    <div className="p-4">
      <h1 className="text-2xl font-bold mb-4">Nmap Scan Result Viewer</h1>
      <div className="flex gap-4 mb-4 flex-wrap">
        <div>
          <label className="block mb-2">Upload Nmap XML:</label>
          <input type="file" accept=".xml" onChange={(e) => handleFileUpload(e, "xml")} />
        </div>
        <div>
          <label className="block mb-2">Upload Grepable/.nmap File:</label>
          <input type="file" accept=".nmap,.gnmap,.txt" onChange={(e) => handleFileUpload(e, "nmap")} />
        </div>
        <div className="flex flex-col">
          <label className="block mb-2">Paste Nmap Output:</label>
          <textarea
            className="border rounded p-2 w-80 h-40"
            value={liveInput}
            onChange={(e) => setLiveInput(e.target.value)}
          />
          <button onClick={handleLivePaste} className="mt-2 px-4 py-2 bg-blue-500 text-white rounded">Parse</button>
        </div>
        <div className="flex items-end gap-2">
          <button onClick={exportToJson} className="px-4 py-2 bg-green-500 text-white rounded">Export to JSON</button>
          <button onClick={exportToCSV} className="px-4 py-2 bg-green-600 text-white rounded">Export to CSV</button>
        </div>
        <div className="flex flex-col">
          <label className="block mb-2">Filter by Port/Service (e.g., http, 443):</label>
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Enter service name or port"
            className="border p-2 rounded"
          />
        </div>
      </div>

      <div>
        <h2 className="text-lg font-semibold mb-2">XML Results</h2>
        {(filterPortData(scanResults.xmlResults || [])).map((host, i) => (
          <div key={i} className="mb-4 border p-3 rounded shadow">
            <h3>Host: {host.address}</h3>
            <ul className="ml-4 list-disc">
              {host.ports.map((port, j) => (
                <li key={j}>
                  Port {port.portId}/{port.protocol} - {port.state} - {port.service}
                  {port.script && <div className="ml-4 text-sm text-gray-600">Vuln: {port.script}</div>}
                </li>
              ))}
            </ul>
          </div>
        ))}

        <h2 className="text-lg font-semibold mb-2 mt-6">Grepable Results</h2>
        {(filterPortData(scanResults.grepResults || [])).map((host, i) => (
          <div key={i} className="mb-4 border p-3 rounded shadow">
            <h3>Host: {host.address}</h3>
            <ul className="ml-4 list-disc">
              {host.ports.map((port, j) => (
                <li key={j}>
                  Port {port.portId} - {port.state} - {port.service}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}
