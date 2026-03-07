// URLScan.io API Integration
// Documentation: https://urlscan.io/docs/api/

const API_KEY = 'API KEY'; //add manually each time

// Get URL from query parameter
function getUrlFromQuery() {
  const params = new URLSearchParams(window.location.search);
  return params.get('url');
}

// Update status message
function setStatus(message, isError = false) {
  const statusEl = document.getElementById('status-message');
  statusEl.textContent = message;
  statusEl.style.color = isError ? 'var(--danger-color)' : 'var(--text-muted)';
}

// Show/hide sections
function showResults() {
  document.getElementById('loading-section').style.display = 'none';
  document.getElementById('results-section').style.display = 'block';
  document.getElementById('liveshot-section').style.display = 'block';
  document.getElementById('details-section').style.display = 'block';
  document.getElementById('recommendations-section').style.display = 'block';
}

// STEP 1: Submit URL for scanning
async function submitScan(url) {
  try {
    const response = await fetch('https://urlscan-backend.vercel.app/api/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'API-Key': API_KEY
      },
      body: JSON.stringify({
        url: url,
        visibility: 'public', // or 'unlisted' or 'private'
        tags: ['gophish', 'phishing-detection']
      })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      console.log('Scan submitted:', data.uuid);
      return data;
    } else {
      console.error('Scan submission failed:', data);
      setStatus(`Error: ${data.message || 'Failed to submit scan'}`, true);
      return null;
    }
  } catch (error) {
    console.error('Error submitting scan:', error);
    setStatus('Error: Unable to connect to scanning service', true);
    return null;
  }
}

// STEP 2: Poll for results (scan takes ~10-30 seconds)
async function waitForResults(uuid, maxAttempts = 30) {
  const resultUrl = `https://urlscan.io/api/v1/result/${uuid}/`;
  
  for (let i = 0; i < maxAttempts; i++) {
    await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds
    
    try {
      const response = await fetch(resultUrl);
      
      if (response.status === 200) {
        const results = await response.json();
        return results;
      } else if (response.status === 404) {
        setStatus(`Scanning website... (${i + 1}/${maxAttempts})`);
        continue;
      } else if (response.status === 410) {
        setStatus('Error: Scan was deleted', true);
        return null;
      }
    } catch (error) {
      console.error('Error fetching results:', error);
    }
  }
  
  setStatus('Error: Scan timed out after 60 seconds', true);
  return null;
}

// STEP 3: Get screenshot and display
async function loadScreenshot(uuid) {
  const screenshotUrl = `https://urlscan.io/screenshots/${uuid}.png`;
  const liveshotImg = document.getElementById('liveshot');
  const placeholder = document.querySelector('.liveshot-placeholder');
  
  try {
    const response = await fetch(screenshotUrl, { method: 'HEAD' });
    
    if (response.ok) {
      liveshotImg.src = screenshotUrl;
      liveshotImg.style.display = 'block';
      placeholder.style.display = 'none';
    } else {
      console.error('Screenshot not available');
      setStatus('Screenshot not available yet', false);
    }
  } catch (error) {
    console.error('Error loading screenshot:', error);
  }
}

// STEP 4: Extract relevant data from results
function parseResults(results) {
  // Extract certificate info
  const cert = results.lists?.certificates?.[0] || {};
  
  // Extract server info
  const serverInfo = results.page?.server || 'Unknown';
  const asn = results.page?.asn || 'Unknown';
  const asnname = results.page?.asnname || '';
  
  // Calculate domain age if available
  const domainAge = results.page?.domain_age_days || null;
  
 // Parse brands correctly - they're objects with a 'name' property
  const brandsArray = results.verdicts?.urlscan?.brands || [];
  const brandNames = brandsArray.map(brand => {
    if (typeof brand === 'string') return brand;
    if (brand && brand.name) return brand.name;
    return null;
  }).filter(Boolean);

  return {
    // Basic page info
    domain: results.page?.domain || 'Unknown',
    ip: results.page?.ip || 'Unknown',
    country: results.page?.country || 'Unknown',
    city: results.page?.city || 'Unknown',
    server: serverInfo,
    title: results.page?.title || 'No title',
    
    // Certificate info
    certIssuer: cert.issuer || 'Unknown',
    certValidFrom: cert.validFrom ? new Date(cert.validFrom * 1000).toLocaleDateString() : 'Unknown',
    certValidTo: cert.validTo ? new Date(cert.validTo * 1000).toLocaleDateString() : 'Unknown',
    certSubject: cert.subject || 'Unknown',
    
    // ASN info
    asn: asn,
    asnname: asnname,
    
    // Domain age
    domainAge: domainAge,
    domainAgeText: domainAge ? `${domainAge} days old` : 'Unknown',
    
    // Security verdicts
    isMalicious: results.verdicts?.overall?.malicious || false,
    score: results.verdicts?.overall?.score || 0,
    brands: brandNames,
    maliciousScore: results.verdicts?.overall?.score || 0,
    categories: results.verdicts?.overall?.categories || [],
    
    // Stats
    totalLinks: results.stats?.uniqIPs || 0,
    requests: results.data?.requests?.length || 0,
    
    // Reputation/blocklists
    engines: results.verdicts?.engines || {},
    
    // URLs
    reportUrl: results.task?.reportURL || '',
    screenshotUrl: results.task?.screenshotURL || ''
  };
}

// Update UI with results
function updateUI(parsed) {
  // Determine verdict
  let verdictClass, verdictText, verdictIcon;
  if (parsed.isMalicious) {
    verdictClass = 'verdict-dangerous';
    verdictText = 'Dangerous';
    verdictIcon = '🚨';
  } else if (parsed.score > 0) {
    verdictClass = 'verdict-suspicious';
    verdictText = 'Suspicious';
    verdictIcon = '⚠️';
  } else {
    verdictClass = 'verdict-safe';
    verdictText = 'Appears Safe';
    verdictIcon = '✅';
  }

  // Get the original URL that was scanned
  const originalUrl = getUrlFromQuery();
  
  // Create the proceed button HTML (only for safe sites)
  const proceedButton = (verdictClass === 'verdict-safe') 
    ? `<a href="${originalUrl}" target="_blank" class="btn btn-secondary" style="margin-left: 1em;">Proceed to Link</a>`
    : '';
  
  // Update verdict section
  document.getElementById('results-section').innerHTML = `
    <h2>Analysis Summary</h2>
    <div class="verdict-badge ${verdictClass}">${verdictIcon} ${verdictText}</div>
    <div class="verdict-summary">
      This website has been analyzed for phishing indicators. Score: ${parsed.score}/100
      ${parsed.brands.length > 0 ? `<br>Mimics brands: ${parsed.brands.join(', ')}` : ''}
      ${parsed.categories.length > 0 ? `<br>Categories: ${parsed.categories.join(', ')}` : ''}
    </div>
    <div style="margin-top: 1.5em;">
      <a href="${parsed.reportUrl}" target="_blank" class="btn">View Full URLScan Report</a>
      ${proceedButton}
    </div>
  `;
  
  // Update Domain Information box
  document.querySelector('.detail-item:nth-of-type(1)').innerHTML = `
    <h4>🌐 Domain Information</h4>
    <p><span class="detail-label">Domain:</span> ${parsed.domain}</p>
    <p><span class="detail-label">Page Title:</span> ${parsed.title}</p>
    <p><span class="detail-label">Domain Age:</span> ${parsed.domainAgeText}</p>
  `;
  
  // Update SSL Certificate box
  document.querySelector('.detail-item:nth-of-type(2)').innerHTML = `
    <h4>🔒 SSL Certificate</h4>
    <p><span class="detail-label">Issuer:</span> ${parsed.certIssuer}</p>
    <p><span class="detail-label">Valid From:</span> ${parsed.certValidFrom}</p>
    <p><span class="detail-label">Valid Until:</span> ${parsed.certValidTo}</p>
    <p><span class="detail-label">Subject:</span> ${parsed.certSubject}</p>
  `;
  
  // Update Server Information box
  document.querySelector('.detail-item:nth-of-type(3)').innerHTML = `
    <h4>📍 Server Information</h4>
    <p><span class="detail-label">IP Address:</span> ${parsed.ip}</p>
    <p><span class="detail-label">Location:</span> ${parsed.city ? `${parsed.city}, ${parsed.country}` : parsed.country}</p>
    <p><span class="detail-label">Server:</span> ${parsed.server}</p>
    <p><span class="detail-label">ASN:</span> ${parsed.asn} ${parsed.asnname ? `(${parsed.asnname})` : ''}</p>
  `;
  
  // Update Risk Indicators box
  const riskIndicators = [];
  if (parsed.domainAge !== null && parsed.domainAge < 30) {
    riskIndicators.push('⚠️ Recently registered domain (less than 30 days)');
  }
  if (parsed.isMalicious) {
    riskIndicators.push('🚨 Flagged as malicious by URLScan');
  }
  if (parsed.score > 50) {
    riskIndicators.push('⚠️ High risk score');
  }
  if (parsed.brands.length > 0) {
    riskIndicators.push(`⚠️ Mimics brand: ${parsed.brands.join(', ')}`);
  }
  
  // Count malicious engine detections
  const enginesData = parsed.engines || {};
  const maliciousEngines = Object.keys(enginesData).filter(key => 
    enginesData[key]?.malicious === true
  );
  
  if (maliciousEngines.length > 0) {
    riskIndicators.push(`🚨 Detected by ${maliciousEngines.length} security engine(s)`);
  }
  
  if (riskIndicators.length === 0) {
    riskIndicators.push('✅ No major risk indicators detected');
  }
  
  document.querySelector('.detail-item:nth-of-type(4)').innerHTML = `
    <h4>🚩 Risk Indicators</h4>
    ${riskIndicators.map(indicator => `<p>${indicator}</p>`).join('')}
  `;
  
  // Update Reputation Score box
  document.querySelector('.detail-item:nth-of-type(5)').innerHTML = `
    <h4>🔍 Reputation Score</h4>
    <p><span class="detail-label">URLScan Score:</span> ${parsed.score}/100</p>
    <p><span class="detail-label">Status:</span> ${parsed.isMalicious ? '⚠️ Flagged as malicious' : '✅ Not flagged'}</p>
    <p><span class="detail-label">Security Engines:</span> ${maliciousEngines.length} flagged it</p>
    <p><span class="detail-label">Categories:</span> ${parsed.categories.join(', ') || 'None'}</p>
  `;
  
  // Update Traffic Analysis box
  document.querySelector('.detail-item:nth-of-type(6)').innerHTML = `
    <h4>📊 Traffic Analysis</h4>
    <p><span class="detail-label">Total Requests:</span> ${parsed.requests}</p>
    <p><span class="detail-label">Unique IPs:</span> ${parsed.totalLinks}</p>
    <p><span class="detail-label">Analysis Date:</span> ${new Date().toLocaleDateString()}</p>
  `;
}

// Main analysis workflow
async function startAnalysis() {
  const url = getUrlFromQuery();
  
  // Display the URL being analyzed
  document.getElementById('url-display').textContent = `Analyzing: ${url}`;
  
  // Validate URL
  if (!url) {
    setStatus('Error: No URL provided in query parameter', true);
    return;
  }
  
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    setStatus('Error: URL must start with http:// or https://', true);
    return;
  }
  
  setStatus('Submitting URL for analysis...');
  
  // Step 1: Submit scan
  const scanData = await submitScan(url);
  if (!scanData) {
    return;
  }
  
  // Step 2: Wait for results
  setStatus('Waiting for scan to complete...');
  const results = await waitForResults(scanData.uuid);
  if (!results) {
    return;
  }
  
  // Step 3: Parse and display results
  setStatus('Analysis complete! Loading results...');
  const parsed = parseResults(results);
  console.log('Parsed data:', parsed);
  
  showResults();
  updateUI(parsed);
  
  // Step 4: Load screenshot
  await loadScreenshot(scanData.uuid);
}

// Auto-start analysis on page load
document.addEventListener('DOMContentLoaded', function() {
  console.log('GoPhish! Analysis page loaded');
  
  // Check if URL parameter exists
  const url = getUrlFromQuery();
  if (url) {
    startAnalysis();
  } else {
    setStatus('Error: No URL provided. Please use the browser extension to analyze a link.', true);
  }
});