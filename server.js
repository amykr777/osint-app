const express = require('express');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
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

// Service Configuration
const serviceEndpoints = {
  ip: ['Virustotal', 'AbuseIPDB', 'IPQualityScore', 'APIVoid', 'XForce'],
  domain: ['Virustotal', 'WhoisXML', 'MetaDataReport', 'APIVoid', 'XForce'],
  hash: ['Virustotal', 'MetaDataReport', 'XForce']
};

// API Service Handlers
const apiServices = {
  Virustotal: async (input) => {
    try {
      const response = await axios.get(
        `https://www.virustotal.com/api/v3/search?query=${encodeURIComponent(input)}`,
        { headers: { 'x-apikey': process.env.VT_API_KEY } }
      );
      const data = response.data.data[0]?.attributes?.last_analysis_stats;
      return data ? `${data.malicious}/${data.harmless + data.malicious} detections` : 'No results';
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
      const response = await axios.get(
        `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${process.env.WHOISXML_KEY}&domainName=${input}&outputFormat=JSON`
      );
      return `Registered: ${response.data.WhoisRecord?.createdDate?.slice(0, 10) || 'Unknown'}`;
    } catch (error) {
      console.error('WhoisXML Error:', error.message);
      return 'Service unavailable';
    }
  },

  MetaDataReport: async (input) => {
    try {
      const response = await axios.get(
        `https://api.metadatareport.com/v1/report?apikey=${process.env.METADATA_KEY}&input=${input}`
      );
      return `Risk Level: ${response.data.risk_level || 'Unknown'}`;
    } catch (error) {
      console.error('MetaDataReport Error:', error.message);
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

  XForce: async (input, type) => {
    try {
      if (!process.env.XFORCE_KEY || !process.env.XFORCE_PASS) {
        throw new Error('X-Force credentials missing');
      }
      
      const auth = Buffer.from(`${process.env.XFORCE_KEY}:${process.env.XFORCE_PASS}`).toString('base64');
      let endpoint;
      
      switch(type) {
        case 'ip': endpoint = `ipr/${input}`; break;
        case 'domain': endpoint = `url/${input}`; break;
        case 'hash': endpoint = `malware/${input}`; break;
        default: return 'Unsupported type';
      }

      const response = await axios.get(
        `https://api.xforce.ibmcloud.com/${endpoint}`,
        { 
          headers: { 
            Authorization: `Basic ${auth}`,
            'Accept': 'application/json'
          },
          validateStatus: () => true
        }
      );

      if (response.status === 401) {
        console.error('X-Force Authentication Failed - Verify API Credentials');
        return 'Authentication failed';
      }

      return type === 'hash' 
        ? `Family: ${response.data.malware?.family?.join(', ') || 'Unknown'}`
        : `Score: ${response.data.result?.score || 'Unknown'}`;
    } catch (error) {
      console.error('X-Force Error:', error.message);
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;