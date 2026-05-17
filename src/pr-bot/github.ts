/**
 * GitHub adapter — posts/updates PR comments via the GitHub REST API.
 *
 * Uses the hidden signature to find and update existing comments (idempotent).
 * Token comes from config.prBot.token OR AL_TRACKER_PR_TOKEN env var.
 */

import { Config } from '../config';
import { PR_COMMENT_SIGNATURE, wrapComment } from './index';

const GITHUB_API = 'https://api.github.com';

function getToken(config: Config): string {
  // SECURITY: Always prefer env var — avoids storing secrets in config.json
  // which is readable via API and written to disk
  const envToken = process.env.AL_TRACKER_PR_TOKEN;
  if (envToken) return envToken;
  if (config.prBot.token) {
    console.warn('[pr-bot] Using token from config.json — prefer AL_TRACKER_PR_TOKEN env var for security');
    return config.prBot.token;
  }
  throw new Error('No GitHub token configured. Set AL_TRACKER_PR_TOKEN environment variable.');
}

function getHeaders(token: string): Record<string, string> {
  return {
    'Authorization': `Bearer ${token}`,
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'Content-Type': 'application/json',
    'User-Agent': 'AL-Companion-Tracker-PR-Bot',
  };
}

/**
 * Find an existing PR comment from the tracker (by signature).
 */
export async function findExistingComment(repo: string, prNumber: number, config: Config): Promise<number | null> {
  const token = getToken(config);
  if (!token) throw new Error('No GitHub token configured. Set AL_TRACKER_PR_TOKEN env var or prBot.token in config.');

  const url = `${GITHUB_API}/repos/${repo}/issues/${prNumber}/comments?per_page=100`;
  const res = await fetch(url, { headers: getHeaders(token) });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub API error (${res.status}): ${text}`);
  }

  const comments = await res.json() as Array<{ id: number; body: string }>;
  const existing = comments.find(c => c.body.includes(PR_COMMENT_SIGNATURE));
  return existing ? existing.id : null;
}

/**
 * Create a new comment on a PR.
 */
export async function createComment(repo: string, prNumber: number, body: string, config: Config): Promise<number> {
  const token = getToken(config);
  if (!token) throw new Error('No GitHub token configured. Set AL_TRACKER_PR_TOKEN env var or prBot.token in config.');

  const url = `${GITHUB_API}/repos/${repo}/issues/${prNumber}/comments`;
  const res = await fetch(url, {
    method: 'POST',
    headers: getHeaders(token),
    body: JSON.stringify({ body: wrapComment(body) }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub API error creating comment (${res.status}): ${text}`);
  }

  const data = await res.json() as { id: number };
  return data.id;
}

/**
 * Update an existing comment.
 */
export async function updateComment(repo: string, commentId: number, body: string, config: Config): Promise<void> {
  const token = getToken(config);
  if (!token) throw new Error('No GitHub token configured. Set AL_TRACKER_PR_TOKEN env var or prBot.token in config.');

  const url = `${GITHUB_API}/repos/${repo}/issues/comments/${commentId}`;
  const res = await fetch(url, {
    method: 'PATCH',
    headers: getHeaders(token),
    body: JSON.stringify({ body: wrapComment(body) }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub API error updating comment (${res.status}): ${text}`);
  }
}

/**
 * Post or update the PR comment (idempotent).
 * If a comment from the tracker already exists, it updates that one.
 * Otherwise, creates a new comment.
 */
export async function postOrUpdateComment(repo: string, prNumber: number, body: string, config: Config): Promise<{ action: 'created' | 'updated'; commentId: number }> {
  const existingId = await findExistingComment(repo, prNumber, config);
  if (existingId) {
    await updateComment(repo, existingId, body, config);
    return { action: 'updated', commentId: existingId };
  } else {
    const newId = await createComment(repo, prNumber, body, config);
    return { action: 'created', commentId: newId };
  }
}

/**
 * Fetch the branch name for a PR from GitHub (so caller doesn't have to know it).
 */
export async function getPRBranch(repo: string, prNumber: number, config: Config): Promise<string> {
  const token = getToken(config);
  if (!token) throw new Error('No GitHub token configured.');

  const url = `${GITHUB_API}/repos/${repo}/pulls/${prNumber}`;
  const res = await fetch(url, { headers: getHeaders(token) });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub API error fetching PR (${res.status}): ${text}`);
  }

  const data = await res.json() as { head: { ref: string } };
  return data.head.ref;
}
