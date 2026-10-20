import re
from collections import Counter

def extract_ips_from_log(file_path):
    """
    Функция читает файл с логами и извлекает все IPv4 адреса.
    """
    # Регулярное выражение для поиска IPv4 адресов (например, 192.168.1.1)
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    extracted_ips = []

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                # Ищем все IP в строке и добавляем в список
                found_ips = re.findall(ip_pattern, line)
                extracted_ips.extend(found_ips)
    except FileNotFoundError:
        print(f"Ошибка: Файл {file_path} не найден.")
        return []

    return extracted_ips

def analyze_logs(file_path, top_n=5):
    """
    Анализирует логи и выводит топ самых частых IP-адресов.
    """
    print(f"--- Анализ логов из файла: {file_path} ---\n")
    ips = extract_ips_from_log(file_path)

    if not ips:
        print("IP-адреса в логах не найдены.")
        return

    # Считаем, сколько раз встречается каждый IP
    ip_counts = Counter(ips)

    print(f"Всего найдено уникальных IP-адресов: {len(ip_counts)}")
    print(f"Топ-{top_n} самых частых IP (возможный брутфорс):")
    
    # Выводим самые частые IP
    for ip, count in ip_counts.most_common(top_n):
        print(f" -> IP: {ip} | Встречается: {count} раз(а)")

if __name__ == "__main__":
    # Имя файла с логами, который мы будем анализировать
    log_file = "sample_auth.log"
    analyze_logs(log_file)
