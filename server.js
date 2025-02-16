const express = require('express');
const path = require('path');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const xml2js = require('xml2js'); // Added for parsing XML responses
require('dotenv').config();

const app = express();

// Trust proxy if behind load balancer
app.set('trust proxy', 1);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate Limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip || '127.0.0.1',
  validate: { trustProxy: true }
});
app.use(limiter);

// Serve static files
app.use(express.static('public'));

// Input Validation
const validateInput = (input) => {
  const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
  const hashRegex = /^[a-fA-F0-9]{32,64}$/;

  if (ipRegex.test(input)) return 'ip';
  if (domainRegex.test(input)) return 'domain';
  if (hashRegex.test(input)) return 'hash';
  return 'unknown';
};

// Service Configuration (Metadefender added for domain and hash)
const serviceEndpoints = {
  ip: ['Virustotal', 'AbuseIPDB', 'APIVoid', 'VPNAPI', 'Hybrid-Analysis', 'Metadefender'],
  domain: ['Virustotal', 'WhoisXML', 'Hybrid-Analysis', 'Metadefender', 'Ismalicious'],
  hash: ['Virustotal', 'Hybrid-Analysis', 'Metadefender']
};

// API Service Handlers
const apiServices = {
  Virustotal: async (input, type) => {
    try {
      let stats;
      if (type === 'hash') {
        // For file hash, use the file lookup endpoint
        const response = await axios.get(
          `https://www.virustotal.com/api/v3/files/${input}`,
          { headers: { 'x-apikey': process.env.VT_API_KEY } }
        );
        stats = response.data.data.attributes.last_analysis_stats;
        if (!stats) return 'No results';
        // Sum all keys: harmless, malicious, suspicious, undetected, timeout
        const total = Object.values(stats).reduce((acc, val) => acc + val, 0);
        return `${stats.malicious}/${total} detections`;
      } else {
        // For IP and domain, use the search endpoint
        const response = await axios.get(
          `https://www.virustotal.com/api/v3/search?query=${encodeURIComponent(input)}`,
          { headers: { 'x-apikey': process.env.VT_API_KEY } }
        );
        stats = response.data.data[0]?.attributes?.last_analysis_stats;
        if (!stats) return 'No results';
        const total = stats.harmless + stats.malicious;
        return `${stats.malicious}/${total} detections`;
      }
    } catch (error) {
      console.error('Virustotal Error:', error.message);
      return 'Service unavailable';
    }
  },

  AbuseIPDB: async (input) => {
    try {
      const response = await axios.get(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${input}`,
        { headers: { Key: process.env.ABUSEIPDB_KEY } }
      );
      return `${response.data.data.abuseConfidenceScore}% malicious score`;
    } catch (error) {
      console.error('AbuseIPDB Error:', error.message);
      return 'Service unavailable';
    }
  },

  IPQualityScore: async (input) => {
    try {
      const response = await axios.get(
        `https://www.ipqualityscore.com/api/json/ip/${process.env.IPQS_KEY}/${input}`
      );
      return `Fraud Score: ${response.data.fraud_score} | VPN: ${response.data.vpn}`;
    } catch (error) {
      console.error('IPQualityScore Error:', error.message);
      return 'Service unavailable';
    }
  },

  WhoisXML: async (input) => {
    try {
      // Call the Whois service with XML output
      const url = `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${process.env.WHOISXML_KEY}&domainName=${input}&outputFormat=XML`;
      const response = await axios.get(url);
      const parser = new xml2js.Parser();
      const result = await parser.parseStringPromise(response.data);
      // Extract createdDate from the parsed XML
      const createdDate = result.WhoisRecord?.createdDate?.[0];
      return `Registered: ${createdDate || 'Unknown'}`;
    } catch (error) {
      console.error('WhoisXML Error:', error.message);
      return 'Service unavailable';
    }
  },

  APIVoid: async (input, type) => {
    try {
      const endpoint = type === 'ip' ? 'iprep' : 'domainrep';
      const response = await axios.get(
        `https://endpoint.apivoid.com/${endpoint}/v1/pay-as-you-go/?key=${process.env.APIVOID_KEY}&${type}=${input}`
      );
      return `Blacklists: ${response.data.data?.report?.blacklists?.detections || 0}`;
    } catch (error) {
      console.error('APIVoid Error:', error.message);
      return 'Service unavailable';
    }
  },

  VPNAPI: async (input) => {
    try {
      const response = await axios.get(
        `https://vpnapi.io/api/${input}?key=${process.env.VPNAPI_KEY}`
      );
      const security = response.data.security;
      return {
        vpn: security.vpn,
        proxy: security.proxy,
        tor: security.tor,
        relay: security.relay
      };
    } catch (error) {
      console.error('VPNAPI Error:', error.message);
      return 'Service unavailable';
    }
  },

  // Hybrid-Analysis handler updated to support hash and non-hash inputs.
  "Hybrid-Analysis": async (input, type) => {
    try {
      if (type === 'hash') {
        // Use the overview endpoint for hash lookups
        const response = await axios.get(
          `https://www.hybrid-analysis.com/api/v2/overview/${input}`,
          {
            headers: {
              'User-Agent': 'Falcon Sandbox',
              'api-key': process.env.HYBRID_ANALYSIS_KEY,
              'accept': 'application/json'
            },
            validateStatus: (status) => status >= 200 && status < 500
          }
        );
        if (response.status === 404) {
          return { verdict: "not found" };
        }
        const verdict = response.data.verdict || "unknown";
        return { verdict };
      } else {
        // For ip and domain, use the search/terms endpoint
        const response = await axios.get(
          `https://www.hybrid-analysis.com/api/v2/search/terms?query=${encodeURIComponent(input)}`,
          {
            headers: {
              'User-Agent': 'Falcon Sandbox',
              'api-key': process.env.HYBRID_ANALYSIS_KEY,
              'accept': 'application/json'
            },
            validateStatus: (status) => status >= 200 && status < 500
          }
        );
        if (response.status === 404) {
          return { verdict: "not found" };
        }
        if (response.data && Array.isArray(response.data) && response.data.length > 0) {
          const verdict = response.data[0].verdict || "unknown";
          return { verdict };
        }
        return { verdict: "unknown" };
      }
    } catch (error) {
      console.error('Hybrid-Analysis Error:', error.message);
      return 'Service unavailable';
    }
  },

  // Metadefender handler updated for hash, domain, and IP.
  Metadefender: async (input, type) => {
    try {
      let url;
      if (type === 'ip') {
        url = `https://api.metadefender.com/v4/ip/${input}`;
      } else if (type === 'hash') {
        url = `https://api.metadefender.com/v4/hash/${input}`;
      } else if (type === 'domain') {
        url = `https://api.metadefender.com/v4/domain/${input}`;
      } else {
        return 'Unsupported type';
      }
      const response = await axios.get(url, {
        headers: {
          'apikey': process.env.METADEFENDER_KEY,
          'accept': 'application/json'
        }
      });
      if (type === 'ip') {
        const detected_by = response.data.lookup_results?.detected_by;
        return { detected_by };
      } else if (type === 'hash') {
        const { threat_name, malware_type, malware_family, total_detected_avs } = response.data;
        return { threat_name, malware_type, malware_family, total_detected_avs };
      } else if (type === 'domain') {
        const detected_by = response.data.lookup_results?.detected_by;
        return { detected_by };
      }
    } catch (error) {
      console.error('Metadefender Error:', error.message);
      return 'Service unavailable';
    }
  },

  // New Ismalicious handler for domain queries.
  Ismalicious: async (input, type) => {
    try {
      if (type !== 'domain') {
        return 'Unsupported type';
      }
      const response = await axios.get(
        `https://ismalicious.com/api/check/reputation?query=${input}`,
        {
          headers: {
            'X-API-KEY': process.env.ISMALICIOUS_KEY,
            'accept': 'application/json'
          }
        }
      );
      const reputation = response.data.reputation;
      return reputation;
    } catch (error) {
      console.error('Ismalicious Error:', error.message);
      return 'Service unavailable';
    }
  }
};

// Main Analysis Endpoint
app.post('/analyze', async (req, res) => {
  try {
    const { input } = req.body;
    
    if (!input || typeof input !== 'string') {
      return res.status(400).json({ error: 'Invalid input format' });
    }

    const inputType = validateInput(input);
    if (inputType === 'unknown') {
      return res.status(400).json({ error: 'Unsupported input type' });
    }

    const results = {};
    const servicesToQuery = serviceEndpoints[inputType];

    await Promise.all(servicesToQuery.map(async (service) => {
      results[service] = await apiServices[service](input, inputType);
    }));

    res.json({ 
      status: 'success',
      inputType,
      results
    });

  } catch (error) {
    console.error('Server Error:', error);
    res.status(500).json({ 
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// Health Check Endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok',
    timestamp: new Date().toISOString()
  });
});

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Default route to serve index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;
