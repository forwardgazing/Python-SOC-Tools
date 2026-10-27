import re
import csv
import ipaddress
from collections import Counter

def extract_ips(file_path):
    """Читает файл и достает все IPv4 адреса"""
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    extracted_ips = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                found_ips = re.findall(ip_pattern, line)
                extracted_ips.extend(found_ips)
    except FileNotFoundError:
        print(f"Ошибка: Файл {file_path} не найден.")
        return []
    return extracted_ips

def filter_external_ips(ips):
    """Оставляет только внешние (белые) IP, отсеивая локальные (серые)"""
    external_ips = []
    for ip in ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Если IP не является локальным (private), добавляем его
            if not ip_obj.is_private and not ip_obj.is_loopback:
                external_ips.append(ip)
        except ValueError:
            continue
    return external_ips

def analyze_and_export(file_path, output_csv="suspicious_ips.csv"):
    """Анализирует логи и сохраняет отчет в CSV"""
    print(f"--- Анализ логов: {file_path} ---")
    
    all_ips = extract_ips(file_path)
    external_ips = filter_external_ips(all_ips)
    
    if not external_ips:
        print("Внешних IP-адресов не найдено.")
        return

    ip_counts = Counter(external_ips)
    
    # Записываем в CSV для Excel
    with open(output_csv, mode='w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file, delimiter=';')
        writer.writerow(['IP-адрес', 'Количество вхождений'])
        
        print(f"Найдено уникальных внешних IP: {len(ip_counts)}")
        print("Топ подозрительных IP (сохранены в CSV):")
        
        for ip, count in ip_counts.most_common():
            print(f" -> {ip} | Встречается {count} раз")
            writer.writerow([ip, count])
            
    print(f"\nОтчет сохранен в файл: {output_csv}")

if __name__ == "__main__":
    analyze_and_export("sample_auth.log")
