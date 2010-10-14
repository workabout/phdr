// ./main   etho   ../all_FTP.pcap   pattern

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <pcre.h>

#define MAX_SIZE_FILENAME 80

char * pattern;
int sum = 0;
char filename[MAX_SIZE_FILENAME];	// имя сохраненного файла для чтения захваченных данных
int packets = 0; 			// количество пакетов, запущенных на чтение
char ch;


int usage (char *progname)
{
	printf("Usage: %s <filename.pcap> <pattern>\n", basename(progname));
	return 0;
}

// Функция print_addrs()
// Записывает IP-адреса источника и назначения из пакетов захвата на стандартный вывод
// Для упрощения предположим следующее о данных захваченных пакетов:
// IP-адреса версии 4 - IPv4;
// Тип линии передачи данных - Ethernet;
// Используется Ethernet в соответствии с RFC 894
// Возвращаемое функцией print_addrs() значение: 
// 0 - успех, 1 - неудача (если пакетная передача была прервана)

void print_addrs(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	int offset = 26;	// 14 байтов для MAC-заголовка
				// смещение - 12 байт в заголовке IP до 
	if (hdr->caplen < 30)
	{
		// захваченных данных недостаточно для извлечения IP-адреса
		fprintf(stderr, "Error: not enough captured packet /*/*data*/*/ present to extract IP addresses. \n");
		exit(1);
	}
	
	if (hdr->caplen >= 34)
	{

		pcre *f; /* переменная для хранения преобразованного шаблона */
	
		const char *errstr; /* буфер для сообщения об ошибке */
		int errchar; /* номер символа */
		int vector[50]; 	/* массив для результатов */
		int vecsize = 50; 	/* размер массива */
		int pairs; 		/* количество найденных пар */
	
		int i,j;
		
		if((f = pcre_compile(pattern,PCRE_CASELESS|PCRE_MULTILINE,&errstr,&errchar,NULL)) == NULL)
		{
			printf("Ошибка: %s\nСимвол N%i\nШаблон:%s\n",errstr,errchar,pattern);
		}
		else
		{
			if((pairs = pcre_exec(f, NULL, (char *) data, hdr->len, 0, PCRE_NOTEMPTY, vector, vecsize)) < 0)
			{
				//printf("Ошибка! Номер: %i\n",pairs);
				//puts("Совпадений не найдено.");
			}
			else
			{
				fprintf(stdout, "\n\n");
				puts(" ********************************************************** Начало пакета ********************************************************** ");
				fprintf(stdout, "Найдено совпадение. Количество подстрок: %i \n",pairs);
				sum += pairs;
			
				for(i=0;i<pairs;i++)
				{
					printf("%i-я подстрока - ",i);
				
					for(j=vector[i*2];j<vector[i*2+1];j++) 
						putchar(data[j]);
						putchar('\n');
						fprintf(stdout, "Смещение в тексте %d: \n", j);
				}
				fprintf(stdout, "Packet received from source address %d %d %d %d \n", data[offset], data[offset+1], data[offset+2], data[offset+3]);
				fprintf(stdout, "and destined for %d %d %d %d \n", data[offset+4], data[offset+5], data[offset+6], data[offset+7]);
				fprintf(stdout, "Length of portion present: %d \n", hdr->caplen);
				fprintf(stdout, "Length this packet: %d \n", hdr->len);
				fprintf (stdout ,"\n");
				puts(" ---------------------------------------------------------------------------------------------------------------------------------");
				fwrite(data, sizeof(char), hdr->len, stdout);	
				fprintf (stdout ,"\n");
			}
		}
	}
	packets++;	// держать запущенными общее количество пакетов на чтение
}

int main(int argc, char **argv)
{
	int ret;
	int cnt  = 0;	
	pcap_t *p;				// дескриптор захваченного пакета
	char errbuf[PCAP_ERRBUF_SIZE];		// буфер для хранения сообщений об ошибках
	char prestr[80];			// префикс строки для ошибок из pcap_perror
	int majver = 0, minver = 0;		// старший и младший номера для текущей версии PCAP-библиотеки

	// Имя интерфейса должно передаеться в программу через комадную строку
	// Имя сохраненного файла может быть передано...
	// Если имя сохраненного файла не передается, pcap_savefile предполагается.
	// Если нет аргументов, программа может быть вызвана неправильно
	
	if ((argc < 2) || (argc > 3))
	{
		usage (argv[0]);
		return 0;
	}
	
	if (strlen (argv[1]) > MAX_SIZE_FILENAME)
	{
		fprintf(stderr, "File name too long. \n");
		return 0;
	}
	strcpy (filename, argv[1]);
	pattern = argv[2];

	// Открыть файл, содержащий данные пакетов захвата. Это должно быть выполнено перед обработкой любого из захваченных пакетов.
	// Файл, содержащий данные захвата, должен быть порожден предыдущим вызовом pcap_open_live().
	
	if (!(p = pcap_open_offline (filename, errbuf)))
	{
		fprintf (stderr, "Error in opening savefile, %s, for reading: %s\n", filename, errbuf);
		return 0;
	}

	// Вызов pcap_dispatch() с переменной count = 0, будет вызывать pcap_dispatch() для чтения или обработки пакетов, 
	// пока не происходит ошибка или EOF. Для каждого считанного из savefile пакета функция print_addrs() будет вызывать печать
	// адресов источника и приемника из заголовка IP в данных захвата. Обратите внимание, что этот пакет по этой причине может не быть полным.
	// Количество данных, полученных в пакете определяется перемнной snaplen, которая передавалась в pcap_open_live(), когда savefile был создан.

	if (pcap_dispatch (p, 0, &print_addrs, (char *) 0) < 0)
	{
		// Вывести соответствующий текст, следующий за ошибкой, сгенерированной библиотекой захваченных пакетов.
		fprintf(stderr, "Error reading packets from %s", filename);
		pcap_perror(p, prestr);
		return 0;
	}
	
	fprintf(stdout, "\nШаблон - \"%s\"",pattern);
	fprintf(stdout, "\nPackets read in: %d", packets);
	fprintf(stdout, "\nОбщее число найденных подстрок: %d", sum);
	
	// Печать номеров старшей и младшей версии. Это номера версий, связанные с просмотром библиотеки пакетов захвата.
	// Номера старшей и младшей версии могут быть использованы, чтобы помочь определить, какая ревизия libcap создала savefile,
	// и, следовательно, какой формат был использован при его написании.
	
	if (! (majver = pcap_major_version(p)))
	{
		fprintf(stderr, "Error getting majer version number from file %s", filename);
		return 0;
	}
	fprintf(stdout, "\nThe major version number used to create the savefile was: %d.", majver);

	if (!(minver = pcap_minor_version(p)))
	{
		fprintf (stderr, "Error getting minor version number from file $s", filename);
		return 0;
	}
	
	fprintf(stdout, "\nThe minor version number used to create the savefile was: %d.\n", minver);
	
	fprintf(stdout, "\n\n");
	
	// pcap_loop (p, 0, &print_addrs, (char *) 0);
	
	// Закройте устройство захвата данных и освободите память, использованную дескриптором захваченных данных.
	printf("ret = %d", ret);
	
	pcap_close(p);
	
	return 0;
}
// ./main f ../term65312.pcap
