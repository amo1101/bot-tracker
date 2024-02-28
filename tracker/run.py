import asyncio
import libvirt
import libvirtaio
import libxml2

async def main(arguments = None):
    sandbox_context = SandboxContext()
    bot_scheduler = Scheduler()
    await bot_scheduler.checkpoint()

if __name__ == "__main__":
    asyncio.run(main())

