import re
import argparse
import json
from collections import Counter
import os

def extract_ips_from_log(file_path):
    """
    Читает файл с логами и извлекает все IPv4 адреса.
    """
    # Более строгое регулярное выражение для поиска валидных IPv4 адресов
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    extracted_ips = []

    if not os.path.exists(file_path):
        print(f"[-] Ошибка: Файл {file_path} не найден.")
        return []

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                found_ips = re.findall(ip_pattern, line)
                extracted_ips.extend(found_ips)
    except Exception as e:
        print(f"[-] Ошибка при чтении файла: {e}")
        return []

    return extracted_ips

def analyze_logs(file_path, top_n=5, output_json=False):
    """
    Анализирует логи, выводит топ IP и опционально сохраняет в JSON.
    """
    print(f"[*] Начинаю анализ файла: {file_path}")
    ips = extract_ips_from_log(file_path)

    if not ips:
        print("[-] IP-адреса в логах не найдены.")
        return

    ip_counts = Counter(ips)
    
    print(f"[+] Всего найдено уникальных IP-адресов: {len(ip_counts)}")
    print(f"[+] Топ-{top_n} самых частых IP (возможный брутфорс):")
    
    top_ips = ip_counts.most_common(top_n)
    for ip, count in top_ips:
        print(f"    -> IP: {ip:15} | Встречается: {count} раз(а)")

    # Сохранение отчета в JSON
    if output_json:
        # Сохраняем ВСЕ найденные IP с их количеством, а не только топ-5
        report_data = dict(ip_counts) 
        report_filename = "scan_report.json"
        
        try:
            with open(report_filename, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=4, ensure_ascii=False)
            print(f"\n[+] Отчет успешно сохранен в файл: {report_filename}")
        except Exception as e:
            print(f"[-] Не удалось сохранить JSON: {e}")

if __name__ == "__main__":
    # Настройка аргументов командной строки (CLI)
    parser = argparse.ArgumentParser(description="Python-утилита для поиска IP-адресов в логах (SOC L1 Tool)")
    parser.add_argument("-f", "--file", required=True, help="Путь к файлу с логами")
    parser.add_argument("-n", "--top", type=int, default=5, help="Сколько топ-IP показать (по умолчанию 5)")
    parser.add_argument("-j", "--json", action="store_true", help="Сохранить результат в JSON файл")
    
    args = parser.parse_args()
    
    analyze_logs(args.file, args.top, args.json)
