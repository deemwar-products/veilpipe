// Mock OpenAI-compatible chat model for the opencode canary: no model spend, and it records EVERY request body, so the
// test can prove what would have reached a real model. Streaming only (opencode streams).
//   node opencode/mock-llm.mjs <port> <log.ndjson>
// A user message containing RUN:<command> gets one bash tool call; any later turn replies "SAW: <user text> | <tool output>".
import { createServer } from 'node:http'
import { appendFileSync } from 'node:fs'
const [port, log] = [Number(process.argv[2] ?? 4791), process.argv[3] ?? 'requests.ndjson']
const text = c => typeof c === 'string' ? c : Array.isArray(c) ? c.map(p => p.text ?? '').join(' ') : ''
createServer((req, res) => {
  let body = ''
  req.on('data', d => (body += d))
  req.on('end', () => {
    if (!req.url.endsWith('/chat/completions')) { res.writeHead(200, { 'content-type': 'application/json' }); return res.end('{"data":[]}') }
    appendFileSync(log, body + '\n')
    const b = JSON.parse(body), msgs = b.messages ?? []
    const lastUser = [...msgs].reverse().find(m => m.role === 'user')
    const lastTool = [...msgs].reverse().find(m => m.role === 'tool')
    const ut = text(lastUser?.content)
    const run = ut.match(/RUN:([^"\n]+)/)
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' })
    const chunk = (delta, finish = null) => res.write(`data: ${JSON.stringify({ id: 'mock', object: 'chat.completion.chunk', created: 0, model: 'echo', choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`)
    // opencode 1.x names its shell tool 'bash', 2.x 'shell'.
    const sh = ['bash', 'shell'].find(n => (b.tools ?? []).some(t => t.function?.name === n))
    if (run && !lastTool && sh) {
      chunk({ role: 'assistant', tool_calls: [{ index: 0, id: 'call_1', type: 'function', function: { name: sh, arguments: JSON.stringify({ command: run[1].trim(), description: 'run it' }) } }] })
      chunk({}, 'tool_calls')
    } else {
      chunk({ role: 'assistant', content: `SAW: ${ut.replace(/\s+/g, ' ').slice(0, 400)} | ${text(lastTool?.content).replace(/\s+/g, ' ').slice(0, 400)}` })
      chunk({}, 'stop')
    }
    res.write(`data: ${JSON.stringify({ id: 'mock', object: 'chat.completion.chunk', created: 0, model: 'echo', choices: [], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } })}\n\n`)
    res.end('data: [DONE]\n\n')
  })
}).listen(port, '127.0.0.1')
