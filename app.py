from flask import Flask, render_template
import requests, re, json
from virus_total_apis import PublicApi as VirusTotalPublicApi

app = Flask(__name__)

@app.route("/")
def hello():
    return render_template("test.html")


@app.route("/whois/<text>")
def whois(text):
    check_ip = text.split(".")[-1]
    try:
        int(check_ip)
        result_text = requests.get("https://who.is/whois-ip/ip-address/" + text,
                                   headers={"User-Agent": "Mozilla/5.0"}).text
        whois_text = re.match('.*<div class="col-md-12 queryResponseBodyKey"><pre>(.*)</pre></div>', result_text,
                              re.DOTALL).group(1)
        return render_template("whois.html", text=whois_text.replace("\n","<br>"))
    except:
        result_text = requests.get(
            "http://api.whoapi.com/?apikey=3fb4ea768efd677bfbed2d705bc6f47a&r=whois&domain=" + text,
            headers={"User-Agent": "Mozilla/5.0"}).text
        if result_text[0]=="{":
            whois_dict = json.loads(result_text)
            reply = "registered: " + str(whois_dict["registered"]) + "\ndate created: " + str(whois_dict["date_created"])
        else:
            reply = "no such domain in record"
        return render_template("whois.html", text=reply.replace("\n","<br>"))

@app.route("/vt/ip/<input>")
def vt_url(input):
    vt = VirusTotalPublicApi('87ab79d0a21d9a7ae5c5558969c7d6b38defa1901b77d27796ae466b3823c776')
    try:
        input_list = [input_item.strip() for input_item in input.split(',')]
        for ip in input_list:
            scan_report = vt.get_url_report(ip)
            return render_template("virustotal.html", text=scan_report)

    except Exception as e:
        return render_template("virustotal.html", text="error")


@app.route("/vt/hash/<input>")
def vt_hash(input):
    vt = VirusTotalPublicApi('87ab79d0a21d9a7ae5c5558969c7d6b38defa1901b77d27796ae466b3823c776')
    try:
        input_list = [input_item.strip() for input_item in input.split(',')]
        for hash in input_list:
            scan_report = vt.get_file_report(hash)
            return render_template("virustotal.html", text=scan_report)

    except Exception as e:
        return render_template("virustotal.html", text="error")

if __name__ == "__main__":
    app.run()


# @app.route("/exp/<input>")
# def exp(input):
#     try:
#         input_list = [input_item.strip() for input_item in input.split(',')]
#         bit_pattern = re.compile("(http:\/\/)?bit.ly\/[a-zA-Z0-9]*")
#         goo_pattern = re.compile("(http:\/\/)?goo.gl\/[a-zA-Z0-9]*")
#
#         for shortened_url in input_list:
#             if goo_pattern.match(shortened_url):
#                 if (shortened_url.find("https://") == -1):
#                     shortened_url = "https://" + shortened_url
#                 response = requests.get('https://www.googleapis.com/urlshortener/v1/url',
#                                         params={'shortUrl': shortened_url,
#                                                 'key': 'AIzaSyBMDM8HM2_K5FHQH14SZIW2sRsvBb3QIo0'})
#                 return render_template("expander.html", text=response.text)
#             elif bit_pattern.match(shortened_url):
#                 if (shortened_url.find("http://") == -1):
#                     shortened_url = "http://" + shortened_url
#                 response = requests.get('https://api-ssl.bitly.com/v3/expand',
#                                         params={'shortUrl': shortened_url,
#                                                 'access_token': '369ebc3d0584dceac891e5fcc457eada2d24c1a3',
#                                                 'format': 'txt'})
#                 return render_template("expander.html", text=response.text)
#
#             else:
#                 raise Exception()
#
#     except Exception as e:
#         return render_template("expander.html", text="error")