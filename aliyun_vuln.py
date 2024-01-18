from datetime import datetime

from app import db, celery
import requests
import re
from app.models import Vulnerability
from utils import except_handling, send_wechat


@celery.task
def get_avd():
    """
    爬取阿里云漏洞库https://avd.aliyun.com/high-risk/list
    """
    try:
        url = "https://avd.aliyun.com/high-risk/list"
        html = requests.get(url).text

        # 使用正则表达式提取标题和链接
        regex = r'<a href="(/detail\?id=AVD-\d+-\d+)"[^>]*>([^<]+)</a>.*?<td>([^<]+)</td>.*?<button[^>]+title="([^"]+)"'

        results = re.findall(regex, html, re.DOTALL)
        for href, id_, title, vuln_type in results[::-1]:
            if not Vulnerability.query.filter_by(title=title.strip()).order_by(Vulnerability.id.desc()).limit(
                    1000).first():
                detail_url = f"https://avd.aliyun.com/detail?id={id_.strip()}"

                detail_response = requests.get(detail_url).text

                cve_pattern = r"CVE-\d{4}-\d+"
                cve = re.search(cve_pattern, detail_response)

                # 披露时间
                date_pattern = r"(\d{4}-\d{2}-\d{2})"
                date = re.search(date_pattern, detail_response)

                # 漏洞详情
                vuln_detail_pattern = r'<div class="text-detail pt-2 pb-4">\s*<div>(.*?)</div>'
                vuln_detail = re.search(vuln_detail_pattern, detail_response)

                # 漏洞来源
                reference_pattern = r'<div class="text-detail pb-3 pt-2 reference">.*?<a href="(.*?)"'
                reference = re.search(reference_pattern, detail_response, re.DOTALL)

                vuln = Vulnerability()
                vuln.title = title.strip()
                vuln.vuln_from = detail_url
                vuln.vuln_type = vuln_type
                vuln.cve = cve.group() if cve else "N/A"
                vuln.detail = vuln_detail.group(1) if vuln_detail else 'No detail found'
                vuln.release_date = date.group() if date else ''
                vuln.reference = reference.group(1) if reference else 'No reference link found'
                vuln.update_date = datetime.now()
                db.session.add(vuln)
                send_wechat('https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=eab30ba3-b650-43a6-9e83-ecea79dadabf',
                            data=f'{title}\n{date.group()}\n{vuln_detail.group(1)}\n{detail_url}')
        db.session.commit()
    except Exception as e:
        return


if __name__ == '__main__':
    get_avd()
