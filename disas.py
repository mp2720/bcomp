#!/usr/bin/env python3

import argparse
import sys
import re

from dataclasses import dataclass
from typing import cast
from enum import Enum


@dataclass
class Instr:
    mnemonic: str
    word: int


class IllegalInstr(Instr):
    def __init__(self, word: int):
        super().__init__('ILLEGAL', word)


@dataclass
class ImplInstr(Instr):
    """ Безадресная команда """
    pass


@dataclass
class IOInstr(Instr):
    opnd: int


@dataclass
class AddrOrImmInstr(Instr):
    """
    Инструкция с прямой абсолютной/относительной адресацией или с прямой загрузкой операнда.
    К ним также относятся JUMP и Bxx.
    """

    class Mode(Enum):
        # * IP, SP - регистры,
        # * [X] - значени ячейки памяти с адресом X,
        # * OPND - 8-битный операнд (если не указано иное), дополненный нулями до 12/16 бит
        #   (в зависимости от контекста).

        IMMEDIATE = 0
        """ Непосредственная: OPND """
        ABSOLUTE_DIRECT = 1
        """ Абсолютная прямая: (OPND - 11 бит): [OPND] """
        IP_RELATIVE_DIRECT = 2
        """ Относительная IP прямая: [IP + OPND] """
        IP_RELATIVE_INDIRECT = 3
        """ Относительная косвенная: [[IP + OPND]] """
        IP_RELATIVE_INDIRECT_INC = 4
        """ 
        Относительная косвенная с постинкрементом: [[IP + OPND]]
        После загрузки [IP+OPND] увеличивается на 1
        """
        IP_RELATIVE_INDIRECT_DEC = 5
        """ 
        Относительная косвенная с постдекрементом: [[IP + OPND]]
        После загрузки [IP+OPND] уменьшается на 1
        """
        SP_RELATIVE_DIRECT = 6
        """ Относительная SP прямая: [SP + OPND] """

    mode: Mode
    opnd: int
    """
    Если режим не IMMEDIATE и SP_RELATIVE_DIRECT, то содержит абсолютный адрес.
    """


def disas_instr(cur_addr: int, word: int) -> tuple[Instr, int | None]:
    """
    @return: дизассемблированная команда и абсолютный адрес, к которому обращается команда
        (если есть).
    """
    opcode = (word & 0xF000) >> 12
    other = word & 0x0FFF

    def ip_rel_to_abs(offset: int) -> int:
        if offset < 128:
            return cur_addr + offset + 1
        else:
            return cur_addr - (256 - offset) + 1

    def impl() -> tuple[ImplInstr, None] | None:
        mnemonics = {
            0x000: 'NOP',
            0x100: 'HLT',
            0x200: 'CLA',
            0x280: 'NOT',
            0x300: 'CLC',
            0x380: 'CMC',
            0x400: 'ROL',
            0x480: 'ROR',
            0x500: 'ASL',
            0x580: 'ASR',
            0x600: 'SXTB',
            0x680: 'SWAB',
            0x700: 'INC',
            0x740: 'DEC',
            0x780: 'NEG',
            0x800: 'POP',
            0x900: 'POPF',
            0xA00: 'RET',
            0xB00: 'IRET',
            0xC00: 'PUSH',
            0xD00: 'PUSHF',
            0xE00: 'SWAP',
        }

        if other not in mnemonics:
            return None

        return ImplInstr(mnemonics[other], word), None

    def io() -> tuple[IOInstr, None] | None:
        mnemonics = {
            0x0: 'DI',
            0x1: 'EI',
            0x2: 'IN',
            0x3: 'OUT',
            0x8: 'INT'
        }
        ext_opcode = (other & 0b111100000000) >> 8
        if ext_opcode not in mnemonics:
            return None

        return IOInstr(mnemonics[ext_opcode], word, other & 0b000011111111), None

    def addr_or_imm() -> tuple[AddrOrImmInstr, int | None] | None:
        bit11 = (other & 0b100000000000) >> 11

        mnemonics = {
            0x2: 'AND',
            0x3: 'OR',
            0x4: 'ADD',
            0x5: 'ADC',
            0x6: 'SUB',
            0x7: 'CMP',
            0x8: 'LOOP',
            # 0x9 reserved
            0xA: 'LD',
            0xB: 'SWAM',
            0xC: 'JUMP',
            0xD: 'CALL',
            0xE: 'ST',
        }

        if opcode not in mnemonics:
            return None

        mnemonic = mnemonics[opcode]

        if bit11:
            mode_bits = (other & 0b011100000000) >> 8
            opnd = other & 0b000011111111
            modes = {
                0b111: AddrOrImmInstr.Mode.IMMEDIATE,
                0b110: AddrOrImmInstr.Mode.IP_RELATIVE_DIRECT,
                0b000: AddrOrImmInstr.Mode.IP_RELATIVE_INDIRECT,
                0b010: AddrOrImmInstr.Mode.IP_RELATIVE_INDIRECT_INC,
                0b011: AddrOrImmInstr.Mode.IP_RELATIVE_INDIRECT_DEC,
                0b100: AddrOrImmInstr.Mode.SP_RELATIVE_DIRECT,
            }

            if mode_bits not in modes:
                return None

            mode = modes[mode_bits]
            if mode not in [
                AddrOrImmInstr.Mode.IMMEDIATE,
                AddrOrImmInstr.Mode.SP_RELATIVE_DIRECT
            ]:
                addr = ip_rel_to_abs(opnd)
                return AddrOrImmInstr(mnemonic, word, mode, addr), addr
            else:
                return AddrOrImmInstr(mnemonic, word, mode, opnd), None

        else:
            addr = other & 0b011111111111
            return AddrOrImmInstr(
                mnemonic,
                word,
                AddrOrImmInstr.Mode.ABSOLUTE_DIRECT,
                addr
            ), addr

    def branch() -> tuple[AddrOrImmInstr, int] | None:
        ext_opcode = (other & 0b111100000000) >> 8
        mnemonics = {
            0: 'BEQ',
            1: 'BNE',
            2: 'BMI',
            3: 'BPL',
            4: 'BHIS',
            5: 'BLO',
            6: 'BVS',
            7: 'BVC',
            8: 'BLT',
            9: 'BGE'
        }

        if ext_opcode not in mnemonics:
            return None

        offset = other & 0b000011111111
        addr = ip_rel_to_abs(offset)

        return AddrOrImmInstr(
            mnemonics[ext_opcode],
            word,
            AddrOrImmInstr.Mode.IP_RELATIVE_DIRECT,
            addr
        ), addr

    match opcode:
        case 0b0000:
            instr = impl()
        case 0b0001:
            instr = io()
        case 0b1111:
            instr = branch()
        case _:
            instr = addr_or_imm()

    if instr is None:
        return IllegalInstr(word), None

    return instr


def dump_prog(
    start_addr: int,
    instrs: list[Instr],
    used_addrs: dict[int, int],
    show_addrs_for_instrs=False,
    show_instr_bin_repr=False,
    russian=False
) -> str:
    EN_TO_RU = {
        'AND': 'И',
        'OR': 'ИЛИ',
        'ADD': 'ПЛЮС',
        'ADC': 'ПЛЮСС',
        'SUB': 'МИНУС',
        'CMP': 'ЧЁ',
        'LOOP': 'КРУГ',
        'LD': 'НЯМ',
        'SWAM': 'ОБМЕН',
        'JUMP': 'ПРЫГ',
        'CALL': 'ВЖУХ',
        'ST': 'ТЬФУ',
        'NOP': 'ПРОП',
        'HLT': 'СТОП',
        'CLA': 'ЧИСТЬ',
        'NOT': 'НЕТЬ',
        'CLC': 'ЧИСТЦ',
        'CMC': 'ИНВЦ',
        'ROL': 'ЦЛЕВ',
        'ROR': 'ЦПРАВ',
        'ASL': 'АЛЕВ',
        'ASR': 'АПРАВ',
        'SXTB': 'ШЫРЬ',
        'SWAB': 'НАОБОРОТ',
        'INC': 'УВЕЛ',
        'DEC': 'УМЕН',
        'NEG': 'ОТРИЦ',
        'POP': 'ВЫНЬ',
        'POPF': 'ВЫНЬФ',
        'RET': 'ВЗАД',
        'IRET': 'ВЗАДП',
        'PUSH': 'СУНЬ',
        'PUSHF': 'СУНЬФ',
        'SWAP': 'МЕНЬ',
        'BEQ': 'БЯКА',
        'BNE': 'БНЕКА',
        'BMI': 'БМИНУС ',
        'BPL': 'БПЛЮС',
        'BHIS': 'БЕЦ',
        'BLO': 'БНЕЦ',
        'BVS': 'БОВЕР',
        'BVC': 'БНЕОВЕР',
        'BLT': 'БМЕНЬ',
        'BGE': 'БНЕМЕНЬ',
        'DI': 'НИЗЯ',
        'EI': 'ЛЬЗЯ',
        'IN': 'СЮДА',
        'OUT': 'ТУДА',
        'INT': 'ПРЕР',
        'ILLEGAL': 'ЧУШЬ',

        'IP': 'СК',
        'SP': 'УС',

        'ORG': 'НАЧ',
        'WORD': 'СЛОВО',
        'label': 'метка'
    }

    def trans(keyword: str) -> str:
        if russian:
            return EN_TO_RU[keyword]
        else:
            return keyword

    lines = []

    def place_org(addr: int):
        if addr is not None:
            lines.append(f'            {trans("ORG"):12}  0x{addr:03x}')

    def place_label(cnt: int, org: int | None = None):
        nonlocal lines

        if len(lines) != 0:
            lines.append('')

        if org is not None:
            place_org(org)

        lines.append(f'{trans("label")}{cnt}:')

    def addr_opnd_to_str(instr: AddrOrImmInstr):
        match instr.mode:
            case AddrOrImmInstr.Mode.IMMEDIATE:
                return f' #0x{instr.opnd:02x}'

            case AddrOrImmInstr.Mode.SP_RELATIVE_DIRECT:
                return f' ({trans("SP")}+{instr.opnd})'

            case _:
                fmt = {
                    AddrOrImmInstr.Mode.ABSOLUTE_DIRECT: ' $%s',
                    AddrOrImmInstr.Mode.IP_RELATIVE_DIRECT: '  %s',
                    AddrOrImmInstr.Mode.IP_RELATIVE_INDIRECT: ' (%s)',
                    AddrOrImmInstr.Mode.IP_RELATIVE_INDIRECT_INC: ' (%s)+',
                    AddrOrImmInstr.Mode.IP_RELATIVE_INDIRECT_DEC: '-(%s)',
                }[instr.mode]

                if instr.opnd in used_addrs:
                    opnd_str = f'{trans("label")}{used_addrs[instr.opnd]}'
                else:
                    opnd_str = f'0x{instr.opnd:03x}'

                return fmt % opnd_str

    for addr, cnt in sorted(used_addrs.items()):
        # Метки, адреса которых находятся за пределами программы нужно как-то объявить.
        # Для этого можно использовать конструкцию вида:
        #
        #    ORG 0xHHH
        # label:
        if addr not in range(start_addr, start_addr + len(instrs)):
            place_label(cnt, addr)

    lines.append('')
    place_org(start_addr)
    lines.append('')

    cur_addr = start_addr
    for instr in instrs:
        if cur_addr in used_addrs:
            place_label(used_addrs[cur_addr])

        line = ''
        if show_addrs_for_instrs:
            line += f'{cur_addr:03x}:'
        else:
            line += ' ' * 4

        if show_instr_bin_repr:
            line += f' {instr.word:04x}'
        else:
            line += ' ' * 5

        line += ' ' * 3

        tr_mnemonic = trans(instr.mnemonic)

        match instr:
            case ImplInstr():
                line += tr_mnemonic
            case IllegalInstr():
                line += f'{trans("WORD"):12}  0x{instr.word:04x}'
            case _:
                line += f'{tr_mnemonic:12}'

                match instr:
                    case IOInstr():
                        line += f'  0x{instr.opnd:02x}'
                    case AddrOrImmInstr():
                        line += addr_opnd_to_str(instr)

        lines.append(line)
        cur_addr += 1

    return '\n'.join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='БЭВМ дизассемблер',
    )
    parser.add_argument(
        'filepath',
        help='Путь к файлу с кодом программы. Если не указать, то читается stdin',
        nargs='?',
        default=None
    )
    parser.add_argument(
        '-x', '--hex',
        help='Считывать программу в формате набора шестнадцатиричных цифр, которые могут быть '
        'разделены пробельными символами. По умолчанию программа считывается в бинарном виде',
        action='store_true'
    )
    parser.add_argument(
        '-o', '--org',
        help='Адрес, который в памяти БЭВМ имеет первое слово входных данных. По умолчанию 0x10',
    )
    parser.add_argument(
        '-a', '--addr',
        help='Добавить в выводе к каждой инструкции её адрес',
        action='store_true'
    )
    parser.add_argument(
        '-b', '--bin',
        help='Добавить в выводе к каждой инструкции её бинарное представление',
        action='store_true'
    )
    parser.add_argument(
        '-r', '--ru',
        help='Выводить мнемоники команд и названия меток на русском',
        action='store_true'
    )
    args = parser.parse_args()

    # Выбрать нужный файл
    if args.filepath is not None:
        file = open(args.filepath, 'r' + ('' if args.hex else 'b'))
    else:
        if args.hex:
            file = sys.stdin
        else:
            file = sys.stdin.buffer

    # Считать программу
    if args.hex:
        text = cast(str, file.read())
        text = re.sub(r'\s', '', text)

        if len(text) & 1:
            raise ValueError(
                "Количество шестнадцатеричных цифр должно быть чётным")

        data = bytearray.fromhex(text)
    else:
        data = cast(bytes, file.read())

    if len(data) & 1:
        raise ValueError(
            "Количество байтов должно быть чётно - БЭВМ работает с 16-битными словами"
        )

    if len(data) == 0:
        raise ValueError("На вход дана пустая программа")

    # Выбрать начальный адрес
    if args.org is not None:
        if args.org.startswith('0x'):
            start_addr = int(args.org, 16)
        else:
            start_addr = int(args.org)
    else:
        start_addr = 0x10

    # Дизассемблировать инструкции
    instrs = []
    used_addrs: dict[int, int] = {}
    cur_addr = start_addr
    for i in range(0, len(data), 2):
        word_bytes = data[i:i + 2]
        word = word_bytes[0] * 256 + word_bytes[1]

        instr, used_addr = disas_instr(cur_addr, word)
        instrs.append(instr)
        if used_addr is not None and used_addr not in used_addrs:
            used_addrs[used_addr] = len(used_addrs) + 1

        cur_addr += 1

    # Вывести программу
    print(dump_prog(
        start_addr,
        instrs,
        used_addrs,
        show_addrs_for_instrs=args.addr,
        show_instr_bin_repr=args.bin,
        russian=args.ru
    ))
