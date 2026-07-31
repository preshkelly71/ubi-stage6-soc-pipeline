import hashlib, json, os

def lf_hash(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    data = data.replace(b'\r\n', b'\n')
    return hashlib.sha256(data).hexdigest()

with open('Makefile', 'r') as f:
    content = f.read()
content = content.replace('python -m pipeline.orchestrator', 'python -m pipeline.main')
with open('Makefile', 'w', newline='\n') as f:
    f.write(content)
print('Fixed Makefile')

with open('README.md', 'r') as f:
    lines = f.readlines()
fixed = []
seen_title = False
for line in lines:
    if line.strip() == '# UBI Stage 6 Project 2: Deception Sensor and Analysis Pipeline':
        if seen_title:
            continue
        seen_title = True
    fixed.append(line)
with open('README.md', 'w', newline='\n') as f:
    f.writelines(fixed)
print('Fixed README')

with open('assessment-manifest.json', 'r') as f:
    manifest = json.load(f)

for fp in ['analysis-pipeline/sessions.parquet', 'analysis-pipeline/clusters.json', 'analysis-pipeline/stix-bundle.json', 'analysis-pipeline/hash-ledger.csv']:
    h = lf_hash(fp)
    manifest['results']['output_hashes'][fp] = h
    print('Updated hash: ' + fp)

manifest['commit'] = 'f4439205c5714a029ac7ea1e0fc2f5c529e1c738'
manifest['commands']['build'] = 'python -m pipeline.main'

with open('assessment-manifest.json', 'w', newline='\n') as f:
    json.dump(manifest, f, indent=2)
    f.write('\n')
print('Fixed assessment-manifest.json')

skip_dirs = {'.git', '.venv', '__pycache__', '.pytest_cache'}
hash_lines = []
for root, dirs, files in os.walk('.'):
    dirs[:] = [d for d in dirs if d not in skip_dirs]
    for fname in sorted(files):
        if fname == 'manifest.sha256' or fname.endswith('.pyc') or fname == 'fix_manifests.py':
            continue
        fullpath = os.path.join(root, fname)
        relpath = os.path.relpath(fullpath, '.').replace('\\', '/')
        if relpath.startswith('replay/raw/'):
            continue
        h = lf_hash(fullpath)
        hash_lines.append(h + '  ' + relpath)

with open('manifest.sha256', 'w', newline='\n') as f:
    f.write('\n'.join(hash_lines) + '\n')
print('Generated manifest.sha256: ' + str(len(hash_lines)) + ' files')
print('DONE')