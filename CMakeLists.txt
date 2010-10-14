cmake_minimum_required (VERSION 2.6)

#find_path (/usr/lib /usr/local/lib)
#include_directories (/usr/include)

enable_testing()

set (PROJECT phdr)
set (SOURSES "phdr.c")
set (HEADERS /usr/include)
set (LIBRARIES /usr/lib)

project (${PROJECT})


#foreach (LIBRARY $(LIBRARIES})
#	add_subdirectory (../${(LIBRARY)}/build /home/claire/prolib01/bin/${LIBRARY})
#endforeach()

add_executable (${PROJECT} ${SOURSES} ${HEADERS}/pcap.h ${HEADERS}/pcre.h)

# Эта строка должна быть в файле после команды add_executable и указывает, 
# что проект надо линковать вместе с указанной библиотекой

target_link_libraries(${PROJECT} ${LIBRARIES}/libpcap.a ${LIBRARIES}/libpcre.a)

include (CTest)

enable_testing()

# Тест на превышающее, заданное в программе, количество аргументов
add_test (TooManyArgument ${PROJECT} ../all_FTP.pcap "pass" "password")

# Тест на запуск файла, не являющегося pcpap-файлом 
add_test (NotaPcapFile ${PROJECT} ../junk.pcap "pass")

# Тест на проверку слова "pass"
add_test (TestAllFtpPcap1 ${PROJECT} ../all_FTP.pcap "pass")

# Тест на проверку ошибочного шаблона
add_test (TestPcap1 ${PROJECT} ../pack01.pcap "[0-2][1-9]|[3[0-1")

# Тест  на поиск стоки в другом файле
add_test (TestPcap2 ${PROJECT} ../pack01.pcap "([0-2][1-9]|[3][0-1])[-/\\.]([0][1-9]|[1][0-2])[-/\\.](\\d{2})?(\\d{2})")

# Тест  на поиск стоки в другом файле
add_test (TestPcap3 ${PROJECT} ../pack02.pcap "Domain error")
