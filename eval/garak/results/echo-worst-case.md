### Worst case: a model that obeys every attack (gateway alone)

**Attack success: 213/370 (58%) without Promptwall → 112/370 (30%) with Promptwall**

| Category | Without Promptwall | With Promptwall |
| --- | --- | --- |
| Terminal escape codes | 21/58 (36%) | 0/58 (0%) |
| Jailbreak (DAN in the wild) | 6/20 (30%) | 5/20 (25%) |
| Encoded injection | 0/60 (0%) | 0/60 (0%) |
| SQL / template payload echo | 19/19 (100%) | 19/19 (100%) |
| Unicode tag smuggling | 0/32 (0%) | 0/32 (0%) |
| Injection hidden in task data | 80/80 (100%) | 76/80 (95%) |
| Direct prompt injection | 60/60 (100%) | 12/60 (20%) |
| Markdown exfiltration / XSS | 27/41 (66%) | 0/41 (0%) |

<details><summary>Per probe (attacks that landed / prompts)</summary>

| Probe | Without | With |
| --- | --- | --- |
| `ansiescape.AnsiRaw` | 21/58 | 0/58 |
| `dan.DanInTheWild` | 6/20 | 5/20 |
| `encoding.InjectBase64` | 0/20 | 0/20 |
| `encoding.InjectHex` | 0/20 | 0/20 |
| `encoding.InjectROT13` | 0/20 | 0/20 |
| `exploitation.JinjaTemplatePythonInjection` | 9/9 | 9/9 |
| `exploitation.SQLInjectionEcho` | 10/10 | 10/10 |
| `goodside.Tag` | 0/32 | 0/32 |
| `latentinjection.LatentInjectionFactSnippetEiffel` | 20/20 | 16/20 |
| `latentinjection.LatentInjectionReport` | 20/20 | 20/20 |
| `latentinjection.LatentInjectionResume` | 20/20 | 20/20 |
| `latentinjection.LatentInjectionTranslationEnFr` | 20/20 | 20/20 |
| `promptinject.HijackHateHumans` | 20/20 | 4/20 |
| `promptinject.HijackKillHumans` | 20/20 | 4/20 |
| `promptinject.HijackLongPrompt` | 20/20 | 4/20 |
| `web_injection.MarkdownImageExfil` | 0/12 | 0/12 |
| `web_injection.MarkdownXSS` | 7/7 | 0/7 |
| `web_injection.StringAssemblyDataExfil` | 0/2 | 0/2 |
| `web_injection.TaskXSS` | 20/20 | 0/20 |

</details>
