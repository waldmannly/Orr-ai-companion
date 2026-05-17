/**
 * Typosquatting & Supply Chain Attack Detection
 * 
 * Checks package install commands across all major ecosystems for:
 * - Typosquats of popular packages (Levenshtein distance)
 * - Scope/namespace confusion (@evil/lodash vs lodash)
 * - Hyphen/underscore swaps (co_lor vs color)
 * - Known malicious package patterns
 * - Dependency confusion (internal-looking names on public registries)
 */

import { RiskSignal } from './classifier';

// ── Popular packages per ecosystem (top targets for typosquatting) ──

const POPULAR_NPM = [
  'express', 'lodash', 'axios', 'react', 'react-dom', 'webpack', 'babel',
  'typescript', 'eslint', 'prettier', 'jest', 'mocha', 'chalk', 'commander',
  'inquirer', 'yargs', 'moment', 'dayjs', 'underscore', 'ramda', 'rxjs',
  'next', 'nuxt', 'vue', 'angular', 'svelte', 'tailwindcss', 'postcss',
  'dotenv', 'cors', 'helmet', 'morgan', 'nodemon', 'pm2', 'socket.io',
  'mongoose', 'sequelize', 'prisma', 'typeorm', 'knex', 'pg', 'mysql2',
  'redis', 'ioredis', 'jsonwebtoken', 'bcrypt', 'passport', 'uuid',
  'puppeteer', 'playwright', 'cheerio', 'sharp', 'multer', 'formidable',
  'winston', 'pino', 'debug', 'colors', 'ora', 'listr', 'blessed',
  'electron', 'vite', 'esbuild', 'rollup', 'parcel', 'turbo', 'nx',
  'fastify', 'koa', 'hapi', 'restify', 'body-parser', 'cookie-parser',
  'cross-env', 'concurrently', 'npm-run-all', 'husky', 'lint-staged',
  'glob', 'minimatch', 'micromatch', 'chokidar', 'fs-extra', 'rimraf',
  'semver', 'node-fetch', 'got', 'superagent', 'request', 'form-data',
];

const POPULAR_PYTHON = [
  'requests', 'flask', 'django', 'fastapi', 'numpy', 'pandas', 'scipy',
  'matplotlib', 'seaborn', 'plotly', 'scikit-learn', 'tensorflow', 'torch',
  'pytorch', 'keras', 'transformers', 'pillow', 'opencv-python', 'boto3',
  'botocore', 'awscli', 'sqlalchemy', 'celery', 'redis', 'psycopg2',
  'pyyaml', 'cryptography', 'paramiko', 'beautifulsoup4', 'lxml', 'scrapy',
  'selenium', 'httpx', 'aiohttp', 'uvicorn', 'gunicorn', 'pytest', 'tox',
  'black', 'flake8', 'mypy', 'pylint', 'isort', 'pydantic', 'click',
  'typer', 'rich', 'colorama', 'setuptools', 'wheel', 'twine', 'pip',
  'virtualenv', 'pipenv', 'poetry', 'jinja2', 'markupsafe', 'werkzeug',
  'marshmallow', 'alembic', 'pygments', 'docutils', 'sphinx',
];

const POPULAR_RUBY = [
  'rails', 'rack', 'sinatra', 'puma', 'sidekiq', 'devise', 'pundit',
  'rubocop', 'rspec', 'capybara', 'nokogiri', 'httparty', 'faraday',
  'activerecord', 'activesupport', 'bundler', 'rake', 'thor', 'pry',
  'byebug', 'dotenv', 'jwt', 'bcrypt', 'redis', 'pg', 'mysql2',
];

const POPULAR_CARGO = [
  'serde', 'tokio', 'reqwest', 'clap', 'rand', 'regex', 'hyper', 'actix-web',
  'rocket', 'diesel', 'sqlx', 'axum', 'tower', 'tracing', 'log', 'env_logger',
  'anyhow', 'thiserror', 'once_cell', 'lazy_static', 'chrono', 'uuid',
  'serde_json', 'toml', 'config', 'dotenv', 'rustls', 'openssl',
];

const POPULAR_GO = [
  'gin', 'echo', 'fiber', 'mux', 'chi', 'cobra', 'viper', 'zap', 'logrus',
  'gorm', 'sqlx', 'redis', 'grpc', 'protobuf', 'jwt', 'testify', 'mock',
];

// ── Package install command parsers ──

interface ParsedInstall {
  ecosystem: string;
  packages: string[];
  flags: string[];
}

/** Extract package names from install commands across all ecosystems */
export function parseInstallCommand(command: string): ParsedInstall | null {
  const cmd = command.trim();

  // npm / yarn / pnpm / bun
  const npmMatch = cmd.match(/\b(npm|yarn|pnpm|bun)\s+(install|i|add)\s+(.+)/i);
  if (npmMatch) {
    const [, , , rest] = npmMatch;
    const packages = extractPackageNames(rest);
    const flags = extractFlags(rest);
    if (packages.length > 0) return { ecosystem: 'npm', packages, flags };
  }

  // pip / pip3 / python -m pip
  const pipMatch = cmd.match(/\b(pip3?|python3?\s+-m\s+pip)\s+install\s+(.+)/i);
  if (pipMatch) {
    const rest = pipMatch[2];
    const packages = extractPackageNames(rest);
    const flags = extractFlags(rest);
    if (packages.length > 0) return { ecosystem: 'pypi', packages, flags };
  }

  // cargo add / cargo install
  const cargoMatch = cmd.match(/\bcargo\s+(add|install)\s+(.+)/i);
  if (cargoMatch) {
    const rest = cargoMatch[2];
    const packages = extractPackageNames(rest);
    const flags = extractFlags(rest);
    if (packages.length > 0) return { ecosystem: 'cargo', packages, flags };
  }

  // gem install
  const gemMatch = cmd.match(/\bgem\s+install\s+(.+)/i);
  if (gemMatch) {
    const packages = extractPackageNames(gemMatch[1]);
    const flags = extractFlags(gemMatch[1]);
    if (packages.length > 0) return { ecosystem: 'rubygems', packages, flags };
  }

  // go get / go install
  const goMatch = cmd.match(/\bgo\s+(get|install)\s+(.+)/i);
  if (goMatch) {
    const rest = goMatch[2];
    const packages = rest.split(/\s+/).filter(p => !p.startsWith('-') && p.length > 0);
    return { ecosystem: 'go', packages, flags: extractFlags(rest) };
  }

  // composer require (PHP)
  const composerMatch = cmd.match(/\bcomposer\s+require\s+(.+)/i);
  if (composerMatch) {
    const packages = extractPackageNames(composerMatch[1]);
    if (packages.length > 0) return { ecosystem: 'composer', packages, flags: extractFlags(composerMatch[1]) };
  }

  // dotnet add package
  const dotnetMatch = cmd.match(/\bdotnet\s+add\s+(?:.*\s+)?package\s+(.+)/i);
  if (dotnetMatch) {
    const packages = extractPackageNames(dotnetMatch[1]);
    if (packages.length > 0) return { ecosystem: 'nuget', packages, flags: extractFlags(dotnetMatch[1]) };
  }

  return null;
}

function extractPackageNames(rest: string): string[] {
  return rest.split(/\s+/)
    .filter(p => !p.startsWith('-') && p.length > 0 && !p.startsWith('/'))
    .map(p => p.replace(/@[\d^~>=<.*]+$/, '')); // strip version specifiers like @^1.0.0
}

function extractFlags(rest: string): string[] {
  return rest.split(/\s+/).filter(p => p.startsWith('-'));
}

// ── Typosquatting Detection ──

/** Levenshtein distance (edit distance) between two strings */
function levenshtein(a: string, b: string): number {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const matrix: number[][] = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      matrix[i][j] = b[i - 1] === a[j - 1]
        ? matrix[i - 1][j - 1]
        : Math.min(matrix[i - 1][j - 1] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j] + 1);
    }
  }
  return matrix[b.length][a.length];
}

/** Normalize a package name for comparison (collapse separators) */
function normalize(name: string): string {
  return name.toLowerCase().replace(/[-_.]/g, '');
}

/** Check if a package name is suspiciously similar to a popular one */
function findTyposquatTarget(pkg: string, popularPackages: string[]): { target: string; reason: string } | null {
  const pkgNorm = normalize(pkg);
  const pkgLower = pkg.toLowerCase();

  for (const popular of popularPackages) {
    const popNorm = normalize(popular);
    const popLower = popular.toLowerCase();

    // Exact match — not a typosquat
    if (pkgLower === popLower) return null;
    if (pkgNorm === popNorm) return null;

    // 1. Levenshtein distance of 1-2 for packages > 3 chars
    if (pkg.length > 3 && popular.length > 3) {
      const dist = levenshtein(pkgLower, popLower);
      if (dist === 1) {
        return { target: popular, reason: `1 character difference from "${popular}" (possible typosquat)` };
      }
      if (dist === 2 && popular.length >= 6) {
        return { target: popular, reason: `2 characters different from "${popular}" (possible typosquat)` };
      }
    }

    // 2. Hyphen/underscore/dot swap (co-lor vs color, co_lor vs color)
    if (pkgNorm === popNorm && pkgLower !== popLower) {
      return { target: popular, reason: `separator confusion with "${popular}" (hyphen/underscore/dot swap)` };
    }

    // 3. Prefix/suffix attacks (lodash-utils, node-express, python-requests)
    const suspiciousPrefixes = ['node-', 'js-', 'python-', 'py-', 'go-', 'rust-', 'ruby-', 'php-'];
    const suspiciousSuffixes = ['-js', '-node', '-py', '-utils', '-helper', '-lib', '-core', '-npm'];
    for (const prefix of suspiciousPrefixes) {
      if (pkgLower === prefix + popLower || pkgLower.replace(prefix, '') === popLower) {
        return { target: popular, reason: `prefix variant of "${popular}" — common typosquat pattern` };
      }
    }
    for (const suffix of suspiciousSuffixes) {
      if (pkgLower === popLower + suffix) {
        return { target: popular, reason: `suffix variant of "${popular}" — common typosquat pattern` };
      }
    }

    // 4. Character repetition (expresss, lodassh)
    if (pkg.length > 4 && popular.length > 4) {
      const pkgDeduped = pkgLower.replace(/(.)\1+/g, '$1');
      const popDeduped = popLower.replace(/(.)\1+/g, '$1');
      if (pkgDeduped === popDeduped && pkgLower !== popLower) {
        return { target: popular, reason: `repeated character variant of "${popular}"` };
      }
    }

    // 5. Transposition (reuqests vs requests)
    if (pkg.length === popular.length && pkg.length > 4) {
      let diffs = 0;
      const positions: number[] = [];
      for (let i = 0; i < pkgLower.length; i++) {
        if (pkgLower[i] !== popLower[i]) {
          diffs++;
          positions.push(i);
        }
      }
      if (diffs === 2 && positions[1] - positions[0] === 1 &&
          pkgLower[positions[0]] === popLower[positions[1]] &&
          pkgLower[positions[1]] === popLower[positions[0]]) {
        return { target: popular, reason: `character transposition of "${popular}"` };
      }
    }
  }

  return null;
}

// ── Scope/Namespace Confusion ──

function checkScopeConfusion(pkg: string, ecosystem: string): string | null {
  // npm: @evil-scope/popular-name
  if (ecosystem === 'npm' && pkg.startsWith('@')) {
    const scopeMatch = pkg.match(/^@[^/]+\/(.+)$/);
    if (scopeMatch) {
      const baseName = scopeMatch[1];
      if (POPULAR_NPM.includes(baseName)) {
        return `Scoped package that shadows popular unscoped package "${baseName}" — possible scope confusion attack`;
      }
    }
  }
  return null;
}

// ── Suspicious install flags ──

function checkSuspiciousFlags(flags: string[], ecosystem: string): string | null {
  const dangerous: Record<string, string[]> = {
    npm: ['--ignore-scripts', '--force', '--legacy-peer-deps'],
    pypi: ['--no-deps', '--no-verify', '--trusted-host', '--index-url', '--extra-index-url'],
    cargo: ['--git'],
    rubygems: ['--no-ri', '--no-rdoc'],
  };

  const dangerousForEcosystem = dangerous[ecosystem] || [];
  for (const flag of flags) {
    if (flag === '--ignore-scripts') {
      // This is actually SAFER (disables postinstall) — not suspicious
      continue;
    }
    if (ecosystem === 'pypi' && (flag === '--index-url' || flag === '--extra-index-url' || flag === '--trusted-host')) {
      return `Custom package index specified (${flag}) — dependency confusion or private registry attack`;
    }
    if (ecosystem === 'npm' && flag === '--registry') {
      return `Custom npm registry specified — dependency confusion attack vector`;
    }
    if (dangerousForEcosystem.includes(flag)) {
      return `Suspicious flag "${flag}" used during install`;
    }
  }
  return null;
}

// ── Internal/Private package name heuristics ──

function checkDependencyConfusion(pkg: string, ecosystem: string): string | null {
  // Internal-looking package names on public registries
  const internalPatterns = [
    /^(internal|private|corp|company|org)-/i,
    /-(internal|private|corp)$/i,
    /^@internal\//i,
  ];
  for (const pat of internalPatterns) {
    if (pat.test(pkg)) {
      return `Package name looks internal ("${pkg}") — possible dependency confusion if installed from public registry`;
    }
  }
  return null;
}

// ── Main Entry Point ──

/**
 * Check a terminal command for typosquatting and supply chain attack indicators.
 * Returns risk signals for any issues found.
 */
export function checkSupplyChain(command: string): RiskSignal[] {
  const signals: RiskSignal[] = [];
  const parsed = parseInstallCommand(command);
  if (!parsed) return signals;

  const { ecosystem, packages, flags } = parsed;

  // Get the right popular packages list
  const popularPackages = getPopularForEcosystem(ecosystem);

  for (const pkg of packages) {
    // Skip obviously internal/scoped packages for Go (they use URLs)
    if (ecosystem === 'go' && pkg.includes('/')) continue;

    // Typosquatting check
    const typosquat = findTyposquatTarget(pkg, popularPackages);
    if (typosquat) {
      signals.push({
        rule: 'typosquat',
        level: 'critical',
        reason: `Package "${pkg}": ${typosquat.reason}`,
        danger: `Typosquatted packages often contain malware that steals credentials, installs backdoors, or exfiltrates source code. The intended package is likely "${typosquat.target}".`,
      });
    }

    // Scope confusion check
    const scopeIssue = checkScopeConfusion(pkg, ecosystem);
    if (scopeIssue) {
      signals.push({
        rule: 'scope_confusion',
        level: 'warn',
        reason: scopeIssue,
        danger: 'Scoped packages that shadow popular packages can trick users into installing malicious code instead of the real package.',
      });
    }

    // Dependency confusion check
    const depConfusion = checkDependencyConfusion(pkg, ecosystem);
    if (depConfusion) {
      signals.push({
        rule: 'dependency_confusion',
        level: 'warn',
        reason: depConfusion,
        danger: 'Dependency confusion attacks publish malicious packages to public registries with internal-looking names, hoping automated builds will pull the public version instead of the private one.',
      });
    }
  }

  // Suspicious flags check
  const flagIssue = checkSuspiciousFlags(flags, ecosystem);
  if (flagIssue) {
    signals.push({
      rule: 'suspicious_install_flags',
      level: 'warn',
      reason: flagIssue,
      danger: 'Unusual install flags can bypass security checks, use untrusted sources, or enable attacks that would otherwise be blocked.',
    });
  }

  return signals;
}

function getPopularForEcosystem(ecosystem: string): string[] {
  switch (ecosystem) {
    case 'npm': return POPULAR_NPM;
    case 'pypi': return POPULAR_PYTHON;
    case 'cargo': return POPULAR_CARGO;
    case 'rubygems': return POPULAR_RUBY;
    case 'go': return POPULAR_GO;
    default: return [...POPULAR_NPM, ...POPULAR_PYTHON];
  }
}
