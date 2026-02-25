# MemoryHandler - Ferramenta de Manipulação de Memória para Linux (Game Cracking)
Este projeto implementa uma classe MemoryHandler em C++ que permite ler e escrever na memória de processos em execução no Linux. Inspirado em ferramentas como Cheat Engine, ele fornece funcionalidades para escanear a memória por valores específicos, encontrar assinaturas (signatures) e padrões (patterns), aplicar payloads e rastrear endereços. Foi desenvolvido como um estudo autônomo sobre conceitos de organização e arquitetura de computadores (OAC1), algoritmos e estruturas de dados(AED2), programação orientada a objetos (POO) e programação paralela.

Funcionalidades

    Anexar a um processo por nome (ex.: "Main Thread" no Left4Dead1).

    Obter base de módulos (ex.: bibliotecas carregadas) e seus tamanhos.

    Buscar assinaturas (sequência exata de bytes) em módulos.

    Buscar padrões (com wildcards, ex.: "48 8B ? ? 00") em módulos.

    Leitura e escrita de qualquer tipo de dado (int, float, etc.) em endereços de memória.

    Escaneamento paralelo de toda a memória do processo para encontrar um valor inicial, utilizando múltiplas threads.

    Refinamento de endereços após mudança de valor (next scan).

    Aplicação de payload em um endereço encontrado por assinatura.

    Congelamento de endereço (freeze) com escrita contínua.
Requisitos

    Sistema Linux (utiliza /proc para acesso à memória).

    Compilador com suporte a C++17 (g++ ou clang++).

    Permissões adequadas para acessar a memória do processo alvo (pode ser necessário executar como root ou ajustar ptrace).

Compilação
    
    g++ -std=c++17 -pthread -o memory_handler main.cpp
Uso Básico

O programa principal (main) oferece um menu interativo para testar as funcionalidades. Ao iniciar, ele tenta anexar ao processo "Main Thread" (nome do executável do Left4Dead1). Você pode modificar o nome do processo no código.

    New scan: Escaneia toda a memória do processo por um valor inicial (ex.: 100). Utiliza threads para acelerar.

    Refine scan: Filtra os endereços encontrados anteriormente, mantendo apenas aqueles cujo valor atual é igual ao novo valor fornecido.

    Show current addresses: Exibe os endereços atualmente na lista e seus valores.

    Freeze an address: Escreve continuamente um valor fixo em um endereço selecionado.

Estrutura da Classe MemoryHandler
Construtores e Destrutor
Constrói o objeto e anexa ao processo pelo nome. O construtor com wchar_t converte para string e chama attach().

    MemoryHandler(const wchar_t* procName) e MemoryHandler(const std::string& procName)

Limpa recursos (apenas zera o PID).

    ~MemoryHandler() 

Percorre o diretório /proc em busca de processos com o nome fornecido. Lê o arquivo comm de cada PID para comparar. Se encontrar, armazena o PID e encerra. Lança exceção se não achar.

    void attach(const std::string& procName)

Lê o arquivo /proc/[pid]/maps e procura pela primeira ocorrência do nome do módulo (ex.: "libc.so.6"). Retorna o endereço inicial da região que contém permissão de execução (x). Se o módulo não for encontrado, retorna 0.

    std::uintptr_t getModuleBaseAddress(const std::string& moduleName)

Similar ao anterior, mas calcula o tamanho total do módulo somando todas as regiões associadas a ele. Retorna o tamanho em bytes.

    size_t getModuleSize(const std::string& moduleName)

Procura uma sequência exata de bytes dentro do módulo. Lê a memória em blocos de 4KB e compara byte a byte. Retorna o endereço onde a assinatura foi encontrada ou 0.

    std::uintptr_t findSignature(const std::string& moduleName, const std::vector<uint8_t>& signature)

Similar a findSignature, mas permite wildcards (representados por "?" ou "??" no padrão). Converte a string do padrão em uma lista de bytes opcionais e faz a busca. Exemplo de padrão: "48 8B ? ? 00".

    std::uintptr_t findPattern(const std::string& moduleName, const std::string& pattern)

Função auxiliar que lê um bloco de memória do processo via /proc/[pid]/mem. Retorna true se a leitura foi bem-sucedida.

    bool readMemoryBlock(uintptr_t addr, uint8_t* buffer, size_t size)

Lê um valor do tipo T no endereço especificado. Lança exceção em caso de falha.

    template<typename T> T readMemory(std::uintptr_t addr)

Escreve um valor do tipo T no endereço. Retorna true se bem-sucedido.

    template<typename T> bool writeMemory(std::uintptr_t addr, T val)

Lê /proc/[pid]/maps e retorna uma lista de regiões de memória que possuem permissão de leitura (r). Ignora regiões muito grandes (acima de 500 MB) para evitar sobrecarga.

    std::vector<MemoryRegion> getValidMemoryRegions()

Realiza um escaneamento paralelo de toda a memória do processo em busca de um valor específico. Divide as regiões de memória entre o número de threads (padrão: hardware concurrency). Cada thread lê blocos de 4KB e compara com o valor. Os endereços encontrados são adicionados a um vetor global com proteção de mutex. Exibe progresso a cada 10%. Retorna todos os endereços que continham o valor no momento do scan.
    
    template<typename T> std::vector<uintptr_t> parallelScan(T value, int numThreads = 0)

Refina uma lista de endereços previamente encontrada: lê o valor atual de cada endereço e mantém apenas aqueles que são iguais ao novo valor. Remove os demais. Útil para o processo de "next scan" em game trainers.

    template<typename T> std::vector<uintptr_t> refineScan(std::vector<uintptr_t>& addresses, T newValue)

Procura uma assinatura no módulo e, se encontrada, escreve o payload (sequência de bytes) a partir do endereço + offset. Retorna true se bem-sucedido.

    bool applyPayLoad(const std::string& moduleName, const std::vector<uint8_t>& signature, const std::vector<uint8_t>& payload, int offset = 0)

Retorna o PID do processo anexado.

    pid_t GetPID() const

Estratégias Adotadas

    Acesso via /proc: Em vez de usar ptrace ou chamadas de sistema específicas, optou-se por ler e escrever diretamente nos arquivos /proc/[pid]/mem e /proc/[pid]/maps. Isso é mais simples e eficiente para leitura em massa.

    Leitura em blocos: Para escaneamento, a memória é lida em blocos de 4KB, reduzindo o número de chamadas de E/S e melhorando o desempenho.

    Paralelismo: O escaneamento inicial divide as regiões de memória entre várias threads, aproveitando múltiplos núcleos da CPU.

    Bufferização: Ao ler a memória, usamos um buffer para evitar acessos individuais a cada byte.

    Wildcards em padrões: O método findPattern permite busca flexível, essencial para signatures que podem variar entre versões de jogos.

    Rastreamento de ponteiros (simplificado): O método refineScan permite ao usuário refinar a busca conforme o valor muda, técnica comum em trainers para achar endereços dinâmicos.

Notas sobre o Desenvolvimento

Este código foi desenvolvido como parte de um estudo autônomo, baseado em conceitos aprendidos nas disciplinas de Organização e Arquitetura de Computadores I (OAC1), Algoritmos e Estruturas de Dados II (AED2), Programação Orientada a Objetos (POO) e tópicos de programação paralela. Devido à natureza autodidata e à falta de experiência prévia com manipulação de memória em Linux, o código pode conter imperfeições, como:

    Tratamento de erros limitado em alguns pontos.

    Possíveis vazamentos de recursos (embora RAII seja usado na maioria).

    Falta de otimizações finas (ex.: alinhamento de cache).

    Uso de std::mutex que pode causar contenção em alguns cenários.

Apesar disso, o código é funcional e serve como base para experimentação e aprendizado. Ele é uma releitura de ferramentas comuns no Windows (que usam APIs como ReadProcessMemory) adaptadas para o ambiente Linux, com alguns diferenciais como o escaneamento paralelo e busca de padrões.
Testes com Left4Dead 1

O programa foi testado com o jogo Left4Dead 1 (executável "Main Thread") em uma distribuição Ubuntu baseada no Windows (WSL). As funcionalidades de scan, refinamento e congelamento funcionaram conforme esperado. Entretanto, devido a particularidades de cada jogo (como proteções anti-cheat), o código pode não funcionar em todos os títulos. Recomenda-se testar em jogos offline ou em seus próprios programas.
