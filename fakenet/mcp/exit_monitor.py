# Copyright 2026 Google LLC
"""Dedicated short-lived Silent Process Exit notification entry."""
import os
import threading
import time


OWNER_RESULT = 'owner-result.json'


def active_bytes(base):
    """Bytes of diagnostics still in progress, with the directory bound.

    Published run directories are archived: they are neither counted nor
    enumerated, so their number and size can never turn into an undeclared
    permanent gate on new collection.  Nothing is deleted to make room.
    """
    used = 0
    count = 0
    entries = []
    if base.is_dir():
        for child in base.iterdir():
            if child.is_dir() and (child / OWNER_RESULT).is_file():
                continue
            entries.append(child)
            if child.is_dir():
                entries.extend(child.rglob('*'))
    for path in entries:
        count += 1
        if count > 10000 or path.is_symlink():
            raise RuntimeError('unbounded/linked exit diagnostic directory')
        if path.is_file():
            used += path.stat().st_size
    return used


def _published(base, path):
    """True for evidence already published by its owning supervisor."""
    try:
        relative = path.relative_to(base)
    except ValueError:
        return False
    if len(relative.parts) < 2:
        return False
    return (base / relative.parts[0] / OWNER_RESULT).is_file()


def main(arguments):
    # The rejection deadline starts before importing the collection modules.
    entered = time.monotonic()
    deadline = [entered + 1]
    done = threading.Event()

    def expire():
        while not done.wait(max(0, min(0.05, deadline[0] - time.monotonic()))):
            if time.monotonic() >= deadline[0]:
                os._exit(124)

    watchdog = threading.Thread(target=expire, name='exit-evidence-deadline', daemon=True)
    watchdog.start()
    guard = target = None
    report = directory = None
    try:
        from fakenet.mcp.exit_intent import notification, claim
        from fakenet.mcp.exit_files import root, read, publish, run_directory, validate_target, digest, QUOTA
        from fakenet.mcp.exit_guard import SingleFlight
        from fakenet.mcp.exit_native import TargetHandle, verify_dump
        from fakenet.mcp.service_stop import process_identity
        observed = notification(arguments)
        guard = SingleFlight()
        if not guard.acquire():
            return 3
        base = root()
        record = validate_target(read(base / 'target.json'), observed['target_pid'])
        directory = run_directory(base, record['run_id'])
        if not directory.is_dir() or (directory / 'entry.json').exists():
            return 3
        target = TargetHandle(record['pid'])
        actual = target.identity()
        if (actual['creation_time'] != record['creation_time']
                or actual['image'].casefold() != record['image'].casefold()
                or target.command_line() != record['command_line']):
            return 3
        helper = process_identity()
        created = int(helper['creation_time']) / 10000000 - 11644473600
        # Include this helper's OS/PyInstaller startup, not just Python entry.
        deadline[0] = min(entered + 60, time.monotonic() + max(0, 60 - (time.time() - created)))
        if time.monotonic() >= deadline[0]:
            return 3
        # All rejected target/duplicate paths above create no persistent output.
        used = active_bytes(base)
        remaining = QUOTA - used - 128 * 1024
        if remaining <= 0:
            raise RuntimeError('global exit diagnostic quota exhausted')
        report = dict(schema='fakenet.exit-result.v1', target=record, notification=observed,
                      helper=helper, observed_time=time.time(), entered_monotonic=entered,
                      deadline_monotonic=deadline[0], complete=False,
                      classification='self_exit' if observed['target_pid'] == observed['initiator_pid']
                      else 'external_termination')
        publish(directory / 'entry.json', dict(target=record, helper=helper,
                acquired=True, deadline_monotonic=deadline[0]))
        # Give the supervisor a chance to pin this helper before a fast dump
        # completes. Its independent handle then proves actual termination.
        while time.monotonic() < deadline[0]:
            try:
                owner = read(directory / 'owner-acquired.json')
            except FileNotFoundError:
                time.sleep(0.02)
                continue
            if owner != dict(target=record, helper=helper):
                raise RuntimeError('owner acquisition acknowledgment mismatch')
            break
        else:
            raise TimeoutError('owner did not pin helper before deadline')
        candidate = claim(directory, record, observed)
        if candidate is not None:
            report['stop_intent_claim'] = candidate
            publish(directory / 'normal-claim.json', dict(claim=candidate, notification=observed))
            # Only the current in-memory supervisor attempt can authorize this
            # waiver. A claimed/stale file by itself never skips the dump.
            claim_deadline = min(deadline[0], candidate['expires_monotonic'])
            while time.monotonic() < claim_deadline:
                try:
                    answer = read(directory / 'normal-ack.json')
                except FileNotFoundError:
                    time.sleep(0.02)
                    continue
                if answer.get('claim') == candidate and answer.get('accepted') is True:
                    report.update(classification='controlled_normal_exit', complete=True,
                                  normal_ack=answer)
                break
        if not report['complete']:
            partial = directory / 'target.dmp.partial'
            report['dump_io'] = target.dump(partial, quota=remaining, deadline=deadline[0])
            size = verify_dump(partial, record['pid'], remaining)
            sha, observed_size = digest(partial, remaining, deadline[0])
            if size != observed_size or time.monotonic() >= deadline[0]:
                raise RuntimeError('dump changed or completed after deadline')
            final = directory / 'target.dmp'
            if final.exists():
                raise RuntimeError('exit dump already exists')
            os.rename(partial, final)
            report.update(complete=True, dump=dict(name='target.dmp', size=size, sha256=sha))
        target.close()
        target = None
        report['target_handle_closed'] = True
        report['completed_monotonic'] = time.monotonic()
        publish(directory / 'result.json', report)
        return 0
    except BaseException as exc:
        if report is not None:
            # The owner will separately verify helper termination; this file
            # never certifies its own process/handle cleanup.
            report.update(complete=False, error=repr(exc)[:512])
            try:
                publish(directory / 'result.json', report)
            except Exception:
                pass
        return 2 if report is not None else 3
    finally:
        if target is not None:
            target.close()
        if guard is not None:
            guard.close()
        done.set()
        watchdog.join(timeout=0.1)


if __name__ == '__main__':
    import sys
    raise SystemExit(main(sys.argv[1:]))
