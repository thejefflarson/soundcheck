// Test case: insecure-output-handling (LLM02:2025)
const Anthropic = require('@anthropic-ai/sdk');
const { exec } = require('child_process');

const client = new Anthropic();

async function renderAIResponse(userQuery) {
  const response = await client.messages.create({
    model: 'claude-opus-4-6',
    max_tokens: 1024,
    messages: [{ role: 'user', content: userQuery }]
  });

  const aiText = response.content[0].text;

  // BUG: renders raw LLM output as HTML — XSS if LLM produces malicious markup
  document.getElementById('output').innerHTML = aiText;
}

async function executeAICode(taskDescription) {
  const response = await client.messages.create({
    model: 'claude-opus-4-6',
    max_tokens: 512,
    messages: [{ role: 'user', content: `Write a bash command to: ${taskDescription}` }]
  });

  const command = response.content[0].text;
  // BUG: executes LLM-generated shell command without validation
  exec(command, (err, stdout) => console.log(stdout));
}
