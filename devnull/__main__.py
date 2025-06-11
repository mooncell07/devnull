from __future__ import annotations
import os
import lightbulb
import hikari
import keystone as k
import capstone as c
from enum import IntEnum
import sys
import math

GUILDS = [1380886371287306371]

class ENDIAN(IntEnum):
    """
    An IntEnum for representing byte order.
    """

    LITTLE = 0
    BIG = 1


class Triplet:
    """
    Generic Storage class for representing the triplet (arch, mode, endian).
    """

    def __init__(self, is_ks, arch, mode, endian):
        """
        is_ks: A flag to check if the triplet belongs to keystone or capstone.
        arch: Hardware Constant.
        mode: Mode Constant.
        _endian: Custom Endian Constant.
        """
        self.is_ks = is_ks
        self.arch = arch
        self.mode = mode
        self._endian = endian

    @property
    def endian(self):
        """
        A property to translate custom Endian to keystone/capstone endian constants.
        """
        if not self.is_ks:
            return (
                c.CS_MODE_LITTLE_ENDIAN
                if self._endian == ENDIAN.LITTLE
                else c.CS_MODE_BIG_ENDIAN
            )
        return (
            k.KS_MODE_LITTLE_ENDIAN
            if self._endian == ENDIAN.LITTLE
            else k.KS_MODE_BIG_ENDIAN
        )


class KS_Targets(IntEnum):
    """
    An IntEnum containing identifiers for various targets.
    .name is name of the architecture + supported mode (Eg: X86_32 where X86=arch and 32=mode).
    .value is a packed integer of the triplet (arch, mode, endian).

    Encoding for .value is as follows:
        $AAMMEE
    where,
        AA: Keystone Hardware Architecture Constant.
        MM: Keystone Mode Constant.
        EE: Flag to identify the byte order.

    * ARM64, HEXAGON and SYSTEMZ do not have a mode so, MM=$00 and shall be ignored.
    """

    ARM = k.KS_ARCH_ARM << 16 | k.KS_MODE_ARM << 8 | ENDIAN.LITTLE
    THUMB = k.KS_ARCH_ARM << 16 | k.KS_MODE_THUMB << 8 | ENDIAN.LITTLE
    X86_16 = k.KS_ARCH_X86 << 16 | k.KS_MODE_16 << 8 | ENDIAN.LITTLE
    X86_32 = k.KS_ARCH_X86 << 16 | k.KS_MODE_32 << 8 | ENDIAN.LITTLE
    X86_64 = k.KS_ARCH_X86 << 16 | k.KS_MODE_64 << 8 | ENDIAN.LITTLE
    MIPS32 = k.KS_ARCH_MIPS << 16 | k.KS_MODE_MIPS32 << 8 | ENDIAN.BIG
    MIPS64 = k.KS_ARCH_MIPS << 16 | k.KS_MODE_MIPS64 << 8 | ENDIAN.LITTLE
    PPC32 = k.KS_ARCH_PPC << 16 | k.KS_MODE_PPC32 << 8 | ENDIAN.BIG
    PPC64 = k.KS_ARCH_PPC << 16 | k.KS_MODE_PPC64 << 8 | ENDIAN.LITTLE
    SPARC = k.KS_ARCH_SPARC << 16 | k.KS_MODE_SPARC32 << 8 | ENDIAN.BIG
    ARM64 = k.KS_ARCH_ARM64 << 16 | ENDIAN.LITTLE
    HEXAGON = k.KS_ARCH_HEXAGON << 16 | ENDIAN.BIG
    SYSTEMZ = k.KS_ARCH_SYSTEMZ << 16 | ENDIAN.BIG


KS_TRIPLETS = {
    t: Triplet(
        is_ks=True,
        arch=(t.value & 0xFF0000) >> 16,
        mode=(t.value & 0x00FF00) >> 8,
        endian=ENDIAN(t.value & 0x0000FF),
    )
    for t in KS_Targets
}

bot = hikari.GatewayBot(token=os.environ["BOT_TOKEN"])
client = lightbulb.client_from_app(bot)
bot.subscribe(hikari.StartingEvent, client.start)


@client.register(guilds=GUILDS)
class Asm(
    lightbulb.SlashCommand,
    name="asm",
    description="Assembles the given Instructions into Machine Code.",
):
    target = lightbulb.integer(
        "target",
        "Pass the hardware Target.",
        choices=[lightbulb.Choice(t.name, t.value) for t in KS_Targets],
    )
    code = lightbulb.string("code", "Pass the assembly instructions.")

    def _get_assembled_bytes(self, triplet):
        try:
            ks = k.Ks(triplet.arch, triplet.mode | triplet.endian)
            data, count = ks.asm(bytes(self.code, "utf-8"))
            return (data, count)
        except k.KsError as e:
            return e

    @lightbulb.invoke
    async def invoke(self, ctx: lightbulb.Context) -> None:
        target = KS_Targets(self.target)
        triplet = KS_TRIPLETS[target]

        result = self._get_assembled_bytes(triplet)
        body = None

        if isinstance(result, k.KsError):
            body = result
        elif result[0] == None:
            body = (
                "Error while parsing the assembly. Are you sure the format is correct?"
            )
        else:
            statements = result[1]
            byte_content = ", ".join(map(str, result[0]))
            hex_content = " ".join([f"{b:02X}" for b in result[0]])
            body = (
                f"; Number of Statements: {statements}\n\n{hex_content} ; {self.code}"
            )

        response = f"""```x86asm\n; Target: {target.name} (Endian: {triplet._endian.name.lower()})\n{body}\n```"""
        await ctx.respond(response)


class CS_Targets(IntEnum):
    """
    Capstone counterpart to KS_Targets.
    """

    ARM = c.CS_ARCH_ARM << 16 | c.CS_MODE_ARM << 8 | ENDIAN.LITTLE
    THUMB = c.CS_ARCH_ARM << 16 | c.CS_MODE_THUMB << 8 | ENDIAN.LITTLE
    ARM64 = c.CS_ARCH_ARM64 << 16 | c.CS_MODE_ARM << 8 | ENDIAN.LITTLE
    X86_32 = c.CS_ARCH_X86 << 16 | c.CS_MODE_32 << 8 | ENDIAN.LITTLE
    X86_64 = c.CS_ARCH_X86 << 16 | c.CS_MODE_64 << 8 | ENDIAN.LITTLE
    MIPS32 = c.CS_ARCH_MIPS << 16 | c.CS_MODE_MIPS32 << 8 | ENDIAN.BIG
    MIPS64 = c.CS_ARCH_MIPS << 16 | c.CS_MODE_MIPS64 << 8 | ENDIAN.LITTLE
    PPC32 = c.CS_ARCH_PPC << 16 | c.CS_MODE_32 << 8 | ENDIAN.BIG
    PPC64 = c.CS_ARCH_PPC << 16 | c.CS_MODE_64 << 8 | ENDIAN.LITTLE


CS_TRIPLETS = {
    t: Triplet(
        is_ks=False,
        arch=(t.value & 0xFF0000) >> 16,
        mode=(t.value & 0x00FF00) >> 8,
        endian=ENDIAN(t.value & 0x0000FF),
    )
    for t in CS_Targets
}


@client.register(guilds=GUILDS)
class Disasm(
    lightbulb.SlashCommand,
    name="disasm",
    description="Disassembles the given Machine Code into relevant Assembly Instructions.",
):
    target = lightbulb.integer(
        "target",
        "Pass the Assembly Target.",
        choices=[lightbulb.Choice(t.name, t.value) for t in CS_Targets],
    )
    code = lightbulb.string("code", "Pass the Binary in Hexadecimal Notation.")

    def _clean_code(self):
        code_string = self.code
        escape_count = 0
        if self.code.startswith("0x"):
            escape_count = 2
        elif self.code.startswith("$") or self.code.startswith("#"):
            escape_count = 1

        code_string = self.code[escape_count:]
        return code_string.replace(" ", "")

    def _get_disassembled_content(self, triplet):
        code_string = self._clean_code()
        length = math.ceil(len(code_string) / 2)
        content = int(code_string, 16).to_bytes(length, byteorder="big", signed=False)

        try:
            md = c.Cs(triplet.arch, triplet.mode | triplet.endian)
            return md.disasm(content, 0x1000)
        except c.CsError as e:
            return e

    @lightbulb.invoke
    async def invoke(self, ctx: lightbulb.Context) -> None:
        target = CS_Targets(self.target)
        triplet = CS_TRIPLETS[target]

        result = self._get_disassembled_content(triplet)
        body = None

        if isinstance(result, c.CsError):
            body = result
        else:
            lines = []
            for i in result:
                lines.append(
                    "0x%X:\t%s\t%s %s"
                    % (
                        i.address,
                        " ".join([f"{int(b):02X}" for b in i.bytes]),
                        i.mnemonic,
                        i.op_str,
                    )
                )
            if len(lines) == 0:
                body = "Idk man, capstone (the disassembler engine this bot uses) didnt return any disassembly nor any errors. Are you sure the opcodes are correct?"
            else:
                body = "\n".join(lines)

        response = f"```x86asm\n; Target: {target.name} (Endian: {triplet._endian.name.lower()})\n\n{body}\n```"
        await ctx.respond(response)


if __name__ == "__main__":
    bot.run()
