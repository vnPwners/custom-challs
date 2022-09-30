// gcc -z execstack -fstack-protector-all -z relro -z now sum.c -o sum -lseccomp

#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>
#include <unistd.h>
#include <string.h>
#include <seccomp.h>

void init()
{
	setbuf(stdin, 0);
	setbuf(stdout, 0);
	setbuf(stderr, 0);
}

void init_seccomp()
{
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_KILL);

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

	seccomp_load(ctx);
}

long long int read_long()
{
	char s[0x20];

	memset(s, 0, 0x20);
	read(0, s, 0x20);
	return atoll(s);
}


// Ret2shellcode
int main()
{
	unsigned long long int num, k = 0, sum = 0;
	long long int *p, longnum;

	init();
	init_seccomp();

	puts("How many number you want to add?");
	printf("> ");
	scanf("%llu", &num);

	p = alloca(num*8);
	memset(p, 0, num*8);
	printf("Opps! Address leak: %p\n", p);

	for (unsigned long long int i=0; i<num; i++, k++)
	{
		printf("p[%llu] = ", i);
		longnum = read_long();
		if (longnum==0)
			break;
		p[i] = longnum;
	}

	for (unsigned long long int i=0; i<k; i++)
		sum += p[i];
	printf("Sum of array: %lld\n", sum);

	return 0;
}