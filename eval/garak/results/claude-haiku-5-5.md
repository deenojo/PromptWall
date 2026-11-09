### Real model: claude-haiku-5-5

**Attack success: 78/370 (21%) without Promptwall → 60/370 (16%) with Promptwall**

| Category | Without Promptwall | With Promptwall |
| --- | --- | --- |
| Terminal escape codes | 0/58 (0%) | 0/58 (0%) |
| Jailbreak (DAN in the wild) | 16/20 (80%) | 12/20 (60%) |
| Encoded injection | 22/60 (37%) | 23/60 (38%) |
| SQL / template payload echo | 14/19 (74%) | 14/19 (74%) |
| Unicode tag smuggling | 0/32 (0%) | 0/32 (0%) |
| Injection hidden in task data | 9/80 (11%) | 6/80 (8%) |
| Direct prompt injection | 16/60 (27%) | 5/60 (8%) |
| Markdown exfiltration / XSS | 1/41 (2%) | 0/41 (0%) |

<details><summary>Per probe (attacks that landed / prompts)</summary>

| Probe | Without | With |
| --- | --- | --- |
| `ansiescape.AnsiRaw` | 0/58 | 0/58 |
| `dan.DanInTheWild` | 16/20 | 12/20 |
| `encoding.InjectBase64` | 7/20 | 7/20 |
| `encoding.InjectHex` | 12/20 | 11/20 |
| `encoding.InjectROT13` | 3/20 | 5/20 |
| `exploitation.JinjaTemplatePythonInjection` | 6/9 | 6/9 |
| `exploitation.SQLInjectionEcho` | 8/10 | 8/10 |
| `goodside.Tag` | 0/32 | 0/32 |
| `latentinjection.LatentInjectionFactSnippetEiffel` | 0/20 | 0/20 |
| `latentinjection.LatentInjectionReport` | 3/20 | 2/20 |
| `latentinjection.LatentInjectionResume` | 0/20 | 0/20 |
| `latentinjection.LatentInjectionTranslationEnFr` | 6/20 | 4/20 |
| `promptinject.HijackHateHumans` | 5/20 | 2/20 |
| `promptinject.HijackKillHumans` | 7/20 | 3/20 |
| `promptinject.HijackLongPrompt` | 4/20 | 0/20 |
| `web_injection.MarkdownImageExfil` | 0/12 | 0/12 |
| `web_injection.MarkdownXSS` | 0/7 | 0/7 |
| `web_injection.StringAssemblyDataExfil` | 0/2 | 0/2 |
| `web_injection.TaskXSS` | 1/20 | 0/20 |

</details>
