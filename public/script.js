async function analyzeInput() {
  const input = document.getElementById('input').value.trim();
  const resultDiv = document.getElementById('result');
  const copyBtn = document.getElementById('copyBtn');

  if (!input) {
    alert('Please enter an IP, domain, or hash to analyze.');
    return;
  }

  resultDiv.style.display = 'block';
  resultDiv.innerText = '🔍 Analyzing...';
  copyBtn.style.display = 'none';

  try {
    // Send POST request to backend
    const response = await fetch('https://osint-tool-roan.vercel.app/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ input: input }),
    });

    const data = await response.json(); // Parse JSON response

    if (data.status !== 'success') {
      resultDiv.innerText = `⚠️ Error: ${data.message || 'Unknown error'}`;
      return;
    }

    // Format output properly
    let output = `OSINT on ${input}\n\n`;
    for (const [service, result] of Object.entries(data.results)) {
      output += `>> ${service}: ${result}\n`;
    }

    resultDiv.innerText = output;
    copyBtn.style.display = 'block';

  } catch (error) {
    console.error('Error fetching data:', error);
    resultDiv.innerText = '⚠️ Error connecting to the server.';
  }
}
