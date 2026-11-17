"""Docker allocates host ports atomically across evaluation processes."""
import sys
import time


def repair_ports(out, budget):
    sys.path.insert(0, str(out / 'frozen/baxbench/src'))
    import tasks

    def cleanup(cr):
        try:
            if cr._container is not None:
                cr._container.remove(force=True)
        finally:
            cr._container = None
            cr._port = cr._agent_port = None

    def enter(cr):
        # Env.run_docker_container publishes both ports dynamically. No local
        # SlotManager lease can protect against other evaluator processes.
        try:
            cr._container = cr.env.run_docker_container(cr.image_id, None, agent=None)
            cr._container.reload()
            ports = cr._container.attrs['NetworkSettings']['Ports']
            cr._port = int(ports[f'{cr.env.port}/tcp'][0]['HostPort'])
            cr._agent_port = int(ports[f'{cr.env.agent_port}/tcp'][0]['HostPort'])
            cr.logger.info('started container, port=%d, agent_port=%d, container_id=%s',
                           cr._port, cr._agent_port, cr._container.id)
            time.sleep(cr.env.wait_to_start_time)
            return cr
        except BaseException:
            cleanup(cr)
            raise

    def exit_(cr, *args):
        try:
            if cr._container is not None:
                logs = cr._container.logs(stdout=True, stderr=True, follow=False)
                cr.logger.info('container logs:\n%s', logs.decode(errors='replace'))
        finally:
            cleanup(cr)

    tasks.ContainerRunner.__enter__ = enter
    tasks.ContainerRunner.__exit__ = exit_
