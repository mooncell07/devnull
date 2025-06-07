from __future__ import annotations
import os
import lightbulb
import hikari
import keystone as k
from enum import IntEnum

class Targets(IntEnum):
    ARM    = k.KS_ARCH_ARM   << 8 | k.KS_MODE_ARM
    THUMB  = k.KS_ARCH_ARM   << 8 | k.KS_MODE_THUMB
    X86_16 = k.KS_ARCH_X86   << 8 | k.KS_MODE_16
    X86_32 = k.KS_ARCH_X86   << 8 | k.KS_MODE_32
    X86_64 = k.KS_ARCH_X86   << 8 | k.KS_MODE_64
    MIPS32 = k.KS_ARCH_MIPS  << 8 | k.KS_MODE_MIPS32
    MIPS64 = k.KS_ARCH_MIPS  << 8 | k.KS_MODE_MIPS64
    PPC64  = k.KS_ARCH_PPC   << 8 | k.KS_MODE_PPC64
    SPARC  = k.KS_ARCH_SPARC << 8 | k.KS_MODE_SPARC32

    #Exceptions
    PPC32_BIG_ENDIAN    = k.KS_ARCH_PPC     << 8 | k.KS_MODE_PPC32
    ARM64_LITTLE_ENDIAN = k.KS_ARCH_ARM64   << 8
    HEXAGON_BIG_ENDIAN  = k.KS_ARCH_HEXAGON << 8
    SYSTEMZ_BIG_ENDIAN  = k.KS_ARCH_SYSTEMZ << 8

class Endian(IntEnum):
    BIG_ENDIAN    = k.KS_MODE_BIG_ENDIAN
    LITTLE_ENDIAN = k.KS_MODE_LITTLE_ENDIAN

KS_ARCH_MODE = {
    target: (((target.value & 0xFF00) >> 8), target.value & 0x00FF)
    for target in Targets
}

bot = hikari.GatewayBot(token=os.environ["BOT_TOKEN"])
client = lightbulb.client_from_app(bot)
bot.subscribe(hikari.StartingEvent, client.start)

@client.register(guilds=[1241346581824016415])
class Asm(
    lightbulb.SlashCommand,
    name="asm",
    description="Assembles the given Instructions into Machine Code.",
):
    target = lightbulb.integer("target", "Pass the hardware target.", choices=[lightbulb.Choice(t.name, t.value) for t in Targets])
    code = lightbulb.string("code", "Pass the assembly instructions.")
    endian = lightbulb.integer("endian", "Endian-ness of the architecture. Ignored in case of Hexagon, PPC32, ARM64, SYSTEMZ.", default=Endian.LITTLE_ENDIAN, choices=[lightbulb.Choice(t.name, t.value) for t in Endian])

    def _get_assembled_bytes(self, arch, mode):
        try:
            ks = k.Ks(arch, mode)
            data, count = ks.asm(bytes(self.code, "utf-8"))
            return (data, count)
        except k.KsError as e:
            return e
    
    @lightbulb.invoke
    async def invoke(self, ctx: lightbulb.Context) -> None:
        target = Targets(self.target)
        arch, mode = KS_ARCH_MODE[target]
        endian = Endian(self.endian)

        if target in (Targets.HEXAGON_BIG_ENDIAN, Targets.SYSTEMZ_BIG_ENDIAN, Targets.PPC32_BIG_ENDIAN):
            endian = Endian.BIG_ENDIAN
        elif target == Targets.ARM64_LITTLE_ENDIAN:
            endian = Endian.LITTLE_ENDIAN

        mode |= endian

        result = self._get_assembled_bytes(arch, mode)
        content = None

        if isinstance(result, k.KsError):
            content = result
        elif result[0] == None:
            content = "Error while parsing the assembly. Are you sure the format is correct?"
        else:
            content =  f"Number of Statements: {result[1]}\n```\n{', '.join(map(str, result[0]))}\n```"

        await ctx.respond(content)

if __name__ == "__main__":
    bot.run()
