from flask import Flask, render_template

import requests, re, json


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
            reply = "registered: " + str(whois_dict["registered"]) + "date created: " + str(whois_dict["date_created"])
        else:
            reply = "no such domain in record"
        return render_template("whois.html", text=reply)


if __name__ == "__main__":
    app.run()
