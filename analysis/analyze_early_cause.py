"""For each EARLY case, determine whether the FP came from Step 1 or LLM."""
import json
from collections import Counter

results = [json.loads(l) for l in open('data/reports/llm_phase2.jsonl') if l.strip()]
early = [r for r in results if r.get('case') == 'EARLY']

step1_caused = []  # EARLY where step1 had FP, LLM agreed it was SAFE (but we ignored)
llm_caused = []    # EARLY where LLM extended to FP
mixed = []

for r in early:
    step1_v = r.get('step1_vuln', 0)
    step2_v = r.get('step2_vuln', 0)
    calls = r.get('llm_calls', [])
    vuln_calls = sum(1 for c in calls if c.get('verdict') == 'VULN')
    safe_calls = sum(1 for c in calls if c.get('verdict') == 'SAFE')

    if step2_v == 0 and step1_v > 0:
        # LLM didn't add anything, step1 is the source
        step1_caused.append((r['cve'], r['repo'], r['dist'], step1_v, step2_v, vuln_calls, safe_calls))
    elif step2_v > 0 and vuln_calls > 0:
        llm_caused.append((r['cve'], r['repo'], r['dist'], step1_v, step2_v, vuln_calls, safe_calls))
    else:
        mixed.append((r['cve'], r['repo'], r['dist'], step1_v, step2_v, vuln_calls, safe_calls))

print(f"Total EARLY cases: {len(early)}")
print(f"  Step 1 caused (step2_vuln=0):   {len(step1_caused)}")
print(f"  LLM caused (step2 extended):     {len(llm_caused)}")
print(f"  Mixed/unclear:                   {len(mixed)}")

print(f"\n=== Step 1 caused EARLY (LLM already knows they're SAFE but we ignored) ===")
print(f"{'CVE':<22} {'Repo':<12} {'Dist':>6} {'S1V':>5} {'S2V':>5} {'VCalls':>6} {'SCalls':>6}")
for r in step1_caused[:20]:
    print(f"{r[0]:<22} {r[1]:<12} {r[2]:>6} {r[3]:>5} {r[4]:>5} {r[5]:>6} {r[6]:>6}")

print(f"\n=== By repo ===")
bc = Counter(r[1] for r in step1_caused)
lc = Counter(r[1] for r in llm_caused)
repos = ['FFmpeg','ImageMagick','curl','httpd','openjpeg','openssl','qemu','wireshark']
print(f'{"Repo":<12} {"Step1-caused":>14} {"LLM-caused":>12}')
for r in repos:
    print(f'{r:<12} {bc.get(r,0):>14} {lc.get(r,0):>12}')
