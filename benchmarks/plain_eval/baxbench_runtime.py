"""Exception-safe container port leases for concurrent BaxBench evaluation."""
from pathlib import Path
import sys
import time
from .common import read_json

ROOT = Path(__file__).resolve().parents[1]

def repair_ports(out, budget):
    sys.path.insert(0, str(out / 'frozen/baxbench/src'))
    import tasks
    from plain_eval import evaluators as evaluator
    config = read_json(out / 'config.json')
    budgets = read_json(out / 'campaign.json')['budgets']
    base = config.get('baxbench_port_base', 18000)
    evaluator.baxbench_port_base = lambda *args: base + 64 * budgets.index(budget)

    def release(cr):
        for name in ('_port', '_agent_port'):
            value = getattr(cr, name)
            if value is not None:
                cr.port_manager.release_slot(value)
                setattr(cr, name, None)

    def enter(cr):
        # Reserve both ports atomically so waiting workers cannot each hold one.
        deadline = time.monotonic() + 300
        while cr._port is None:
            manager = cr.port_manager
            with manager.lock:
                free = [i for i, available in enumerate(manager.slots) if available]
                if len(free) >= 2:
                    a, b = free[:2]
                    manager.slots[a] = manager.slots[b] = False
                    cr._port, cr._agent_port = a + manager.min, b + manager.min
            if cr._port is None:
                if time.monotonic() > deadline:
                    raise TimeoutError('No BaxBench port pair available after 300 seconds')
                time.sleep(.1)
        try:
            cr._container = cr.env.run_docker_container(cr.image_id, cr._port, agent=cr._agent_port)
            cr.logger.info('started container, port=%d, agent_port=%d, container_id=%s',
                           cr._port, cr._agent_port, cr._container.id)
            time.sleep(cr.env.wait_to_start_time)
            return cr
        except BaseException:
            try:
                if cr._container is not None:
                    cr._container.remove(force=True)
            finally:
                release(cr)
            raise

    def exit_(cr, *args):
        try:
            if cr._container is not None:
                logs = cr._container.logs(stdout=True, stderr=True, follow=False)
                cr.logger.info('container logs:\n%s', logs.decode(errors='replace'))
        finally:
            try:
                if cr._container is not None:
                    try:
                        cr._container.remove(force=True)
                    except Exception:
                        pass
            finally:
                release(cr)

    tasks.ContainerRunner.__enter__ = enter
    tasks.ContainerRunner.__exit__ = exit_
