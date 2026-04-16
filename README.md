# Model Combat

### AI models are writing more code. But can they secure it?

Everyone is racing to generate code faster. But if AI is pushing more code into the world, the real question is not just whether models can write code — it's whether we can **trust** the code they write.

![Title Screen](docs/ss/title.png)

---

## The Problem: Benchmarks Are Broken

**Current coding benchmarks don't look like real engineering.**

Most benchmarks are tiny tasks, toy bugs, or isolated puzzles. Real engineering is messy: big repos, user accounts, sessions, APIs, files, permissions, and state. Security work is even messier — the model has to **find** the bug, **prove** it matters, and **patch** it without breaking everything else.

---

## Our Idea: The Best Security Benchmark Is a CTF

We built **Model Combat**: a CTF-style benchmark where AI models fight inside real vulnerable repositories. Each model gets services with hidden vulnerabilities. They have to find bugs, exploit them, patch them, and defend their own code.

![Vulnerability Pool](docs/ss/pool.png)

---

## How It Works

### Find. Exploit. Patch. Survive.

```
Real repos → Vulnerability pool → Model agents → Live round → Judge → Scoreboard
```

We run multiple rounds. Models earn points for:
- **Valid findings** — discovering real vulnerabilities
- **Working exploits** — proving the bug is exploitable
- **Correct patches** — fixing the issue without breaking the app
- **Surviving attacks** — defending their own code from other models

This lets us compare models not by vibes, but by **security engineering performance**.

![Lobby — Choose Your Fighters](docs/ss/lobby.png)

### The Roster

| Fighter  | Model           | Trait             |
|----------|-----------------|-------------------|
| Scorpion | GPT-5.4         | Exploit pressure  |
| Sub-Zero | Claude Opus 4.6 | Patch precision   |
| Raiden   | Gemini 2.0      | Fast balance      |
| Liu Kang | Llama 4         | Open source climb |

---

## Why It's Real

**10 real self-hosted apps. TypeScript judge. Repeatable rounds.**

We built this around a curated repo pool: apps like BookStack, Gogs, File Browser, Miniflux, Etherpad, Wekan, ntfy, and more. These are real multi-user systems with real attack surfaces.

Our judge provisions rounds, validates flags, records traces, checks patches, and scores outcomes.

![Arena — Live Match](docs/ss/arena.png)

### The Arena

And because benchmarks are usually boring, we made the whole thing **watchable**.

Models become fighters. Vulnerabilities become attacks. Patches become defenses. You can literally watch GPT, Claude, Gemini, and Llama fight through a security tournament — complete with:

- **"ROUND 1... FIGHT!"** intro sequence
- Real-time HP bars that drain as attacks land
- Live terminal feed of exploits, patches, and defenses
- Animated UMK3 fighter sprites
- Mid-match callouts and a fighter queue

---

## Results

At the end, we get something much better than a static benchmark score. We get a **real leaderboard** showing which model can actually operate like a security engineer.

![Results](docs/ss/results.png)

![Benchmark](docs/ss/benchmark.png)

---

## The Pitch (2 minutes)

> Hey everyone, we built **Model Combat**.
>
> AI models are getting insanely good at generating code. But that creates a new problem: if we're producing more code faster than ever, how do we know that code is actually safe?
>
> Current coding benchmarks don't really answer that. Most of them are tiny tasks, toy bugs, or isolated puzzles. But real engineering is messy. You have big repos, user accounts, sessions, permissions, files, state, and weird edge cases. And security work is even harder, because a model has to not only write code, but find vulnerabilities, prove they're exploitable, and patch them without breaking the app.
>
> So we asked: what's the best way to evaluate security?
>
> **A CTF.**
>
> Model Combat is a CTF-style benchmark where AI models compete inside real vulnerable repositories. Each model gets access to services with hidden vulnerabilities. They have to find bugs, exploit them, patch them, and defend their own code.
>
> We run multiple rounds across different kinds of apps: knowledge systems, stateful utilities, and realtime collaboration tools. The pool includes real self-hosted apps like BookStack, Gogs, File Browser, Miniflux, Etherpad, Wekan, and ntfy.
>
> Behind the scenes, we built a TypeScript judge that provisions rounds, validates flags, records traces, checks patches, and scores the models. Models earn points for valid findings, working exploits, correct fixes, and surviving attacks.
>
> And because benchmarks are usually boring, we made it watchable. In the UI, models become fighters. Vulnerabilities become attacks. Patches become defenses. You can literally watch GPT, Claude, Gemini, and Llama fight through a security tournament.
>
> At the end, we learn which model can actually operate like a security engineer.
>
> **Model Combat is the benchmark for the AI-generated code era: find, exploit, patch, survive.**

---

## Tech Stack

- **Next.js 16** — App Router, Turbopack
- **React 19** — client-side state, no SSR complexity
- **Pure CSS** — CRT scanlines, pixel grid overlays, MK theme
- **VT323 + custom Mortal Kombat fonts**
- Sprite assets from [MK Warehouse](https://www.mortalkombatwarehouse.com/)

## Getting Started

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

## Project Structure

```
app/
  page.tsx          # All screens: title, pool, lobby, arena, results, benchmark
  globals.css       # Full stylesheet (CRT effects, MK theme, responsive)
  layout.tsx        # Root layout

public/
  mk-assets/
    sprites/        # Stance GIFs — scorpion, subzero, liukang, raiden
    arena/          # Stage backgrounds and VS stinger
    sounds/         # Hit, block, found, patch, KO, round-over clips
    fx/             # Impact burst, flame overlays
  fonts/            # Mortal Kombat 1 + MK Title custom fonts
  logo.png          # Dragon emblem
```

## Adding Screenshots

```bash
mkdir -p docs/ss
# Save screenshots as:
#   docs/ss/title.png
#   docs/ss/pool.png
#   docs/ss/lobby.png
#   docs/ss/arena.png
#   docs/ss/results.png
#   docs/ss/benchmark.png
```

---

**Model Combat** — the benchmark for the AI-generated code era.
