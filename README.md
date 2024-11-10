# bcomp (Basic Computer)
This is simple computer model studied in ITMO University since 1982 by first year students. 
Its features are simple instructions set (inspired from PDP-8 and PDP-11), simple microprogram model and logic scheme to easy learn basics of computer architecture.

All documentation is unfortunativelly in Russian. You can look at https://se.ifmo.ru/courses/csbasics for details.
There is also lectures track on https://www.youtube.com/playlist?list=PLBWafxh1dFuwbs2bc_ba_1FIm4SzFYg2p

There are two branches for old model v1 (this model was studied until year 2019) and next generation model v2 (current).
Folder "docs" is for old model and would be deleted in the future for v2. 


## ЛР 2, 3

Для работы `ocr.py` надо установить `PIL`:

```bash
pip install pillow
```

Программа даётся в виде картинки с машинным кодом. Для считывания текста нужно выполнить команду
```bash
./ocr.py VARIANT.png OUTPUT_TEXT 
```

Затем программу можно дизассемблировать так:
```bash
./disas.py OUTPUT_TEXT -f=lab
```

По умолчанию дизассемблер выводит программу в виде, совместимом с ассебмлером БЭВМ.
Дополнительные опции `-a` и `-b` дают больше полезной информации, но ассемблер такое не примет.

Полный список опций можно посмотреть так
```bash
./disas.py -h
```

Дизассемблер вставит нумерованные метки на **все** адреса, которые встречаются в качестве операндов
инструкций.

Код и данные программы БЭВМ хранятся в одной памяти и дизассемблер не может их отличить друг от друга,
поэтому он пытается разобрать все слова. Если какое-то слово вообще не может быть инструкцией для
базовой микропрограммы, то в вывод будет вставлена псевдоинструкция ассемблера `WORD 0xXXXX`.

Тем не менее, даже если какое-то слово было ошибочно воспринято как инструкция, при компиляции
того, что вывел дизассемблер, на выходе получится программа, идентичная изначальной.

Ещё дизассемблер не вставляет метку `START`. Если я правильно понял, то она должна быть там, где
на картинке варианта стоит `+`.

Про ассемблер можно прочитать в Приложении Д методических указаний на
https://se.ifmo.ru/courses/csbasics

