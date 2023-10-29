import tomli
import logging.config
from pathlib import Path
from minicli import cli, run
from microfarm_pki.workers.minter impoet Minter
from microfarm_pki.workers.ocsp import Responder


@cli
async def serve(config: Path) -> None:
    assert config.is_file()
    with config.open("rb") as f:
        settings = tomli.load(f)

    if logconf := settings.get('logging'):
        logging.config.dictConfigClass(logconf).configure()

    # debug
    logger = logging.getLogger('peewee')
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)

    manager = Manager(settings['database']['url'])
    manager.register(Request)
    manager.register(Certificate)

    async with manager:
        async with manager.connection():
            await manager.create_tables()

    service = PKIService(
        manager,
        settings['amqp']['url'],
        settings['amqp']
    )
    server = await rpc.serve_rpc(service, bind={settings['rpc']['bind']})
    print(f" [x] PKI Service ({settings['rpc']['bind']})")
    await service.persist()
    server.close()


@cli
async def work(config: Path):
    assert config.is_file()
    with config.open("rb") as f:
        settings = tomli.load(f)

    if logconf := settings.get('logging'):
        logging.config.dictConfigClass(logconf).configure()

    pki: PKI = load_pki(settings['pki'])
    minter = Minter(pki)
    responder = Responder(pki)

    await asyncio.gather(
        minter.listen(settings['amqp']['url'], settings['amqp']['queues']),
        responder.listen(settings['amqp']['url'])
    )


@cli
def generate(config: Path):
    assert config.is_file()
    with config.open("rb") as f:
        settings = tomli.load(f)

    create_pki(settings['pki'])


if __name__ == '__main__':
    run()
