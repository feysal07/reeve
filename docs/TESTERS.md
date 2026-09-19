# Reeve: trial brief

Thanks for helping. This should cost you five minutes, or a week of doing nothing
differently, depending on which part you take on.

## What Reeve is

Most of us now run more than one AI coding agent. Each vendor ships its own admin
console, its own policy file and its own telemetry format, and none of them can see the
others. Reeve is one tool that reads all of them: what is installed, what it is allowed
to do, what it costs, and what a policy would have stopped.

It is early. The point of this trial is to find out where it is wrong.

## Part 1: the scan, five minutes, read-only

```
reeve scan
```

That is the whole thing. It reads the configuration of any supported agent on your
machine and prints what it found. It writes nothing, changes nothing, and makes no
network calls.

**What I would like from you:**

```
reeve scan --json > reeve-scan.json
```

Send me that file, plus answers to three questions:

1. **Did anything surprise you?** A finding you did not know applied to your machine is
   the signal that discovery is worth building. Nothing surprising is also a result.
2. **Do you disagree with any finding?** If a finding is wrong, or right but not worth
   raising, say so. A tool that cries wolf gets ignored, and I would rather cut rules
   than lose your attention.
3. **Could you read it without me explaining it?** If a finding needed a translation,
   the finding is badly written.

The JSON contains file paths, agent settings, MCP server names and the names of
environment variables. It does **not** contain any variable's value, any credential,
any prompt or any file content. Open it and check before sending if you like.

## Part 2: the trial, one week, nothing blocked

This one needs a volunteer, because it adds a hook to your own Claude Code.

```
reeve trial install
```

It runs in **dry run**: it evaluates every tool call against a small policy, records
what it would have done, and then allows the action regardless. Nothing you do is
blocked or slowed in any way you will notice.

It backs up your settings first, adds exactly one hook, and touches nothing else. To
check at any time:

```
reeve trial status
```

To stop:

```
reeve trial uninstall
```

That removes only the hook it added. Hooks you wrote yourself are left alone.

**Then use Claude Code exactly as you normally would, for about a week.** This is the
important part and the easiest to get wrong. Do not avoid commands because you think
they might trip the policy, and do not try to trip it on purpose. The question is
whether this policy would have interrupted ordinary work, and that only shows up if the
work is ordinary.

At the end:

```
reeve trial report
```

Send me that output and the log file it names.

## What I am actually trying to find out

Being straight about this, so you know what counts as a useful week.

**The false positive rate is the whole question.** A policy that blocks real work gets
switched off within a day, and then it protects nothing. If the report shows a rule
fired on something you consider a perfectly normal thing to do, that is the most
valuable result this trial can produce. It means the rule is wrong, and I would rather
learn that from you than from someone who has already stopped using the tool.

So when you send the report, for anything under "Rules fired", add a line about what
you were doing at the time. One sentence is plenty.

**Second: is anything missing?** If you did something during the week that you think
*should* have been flagged and was not, that is equally useful.

**Third: did you notice it at all?** The guard runs before every tool call. It should be
invisible. If Claude Code felt slower, say so.

## What is recorded, and what is not

The decision log contains, per tool call: the time, which agent, the tool name, the
command line or file path, what the policy decided and which rule decided it.

It does **not** contain prompts, model responses, file contents, or the value of any
environment variable. There is a test in the project that fails if that ever changes.

Everything stays on your machine until you choose to send it. Nothing is uploaded, and
Reeve makes no network connections at all except the collector, which is not part of
this trial.

Read the log yourself before sending it:

```
reeve trial report
```

## If something goes wrong

Uninstall first, then tell me:

```
reeve trial uninstall
```

Your original settings are kept at `~/.reeve/settings.json.before-reeve`, so you can
always restore them by hand.

If Claude Code starts behaving oddly at any point, uninstalling should fix it
immediately, and I would very much like to know. That is a bug worth more than the rest
of the trial.
