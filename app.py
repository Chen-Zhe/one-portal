from flask import Flask, render_template, send_from_directory
import requests, re, json
from virus_total_apis import PublicApi as VirusTotalPublicApi

import numpy as np
from sklearn import manifold
import random


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
            return render_template("vt-url.html", url_request=scan_report.get("results").get("url").replace(":", "[:]").replace(".", "[.]"),
                                   scan_date=scan_report.get("results").get("scan_date"),
                                   positives=scan_report.get("results").get("positives"),
                                   total=scan_report.get("results").get("total"),
                                   link=scan_report.get("results").get("permalink"))

    except Exception as e:
        return render_template("vt-url.html", text="Error: Please try again.")


@app.route("/vt/hash/<input>")
def vt_hash(input):
    vt = VirusTotalPublicApi('87ab79d0a21d9a7ae5c5558969c7d6b38defa1901b77d27796ae466b3823c776')
    try:
        input_list = [input_item.strip() for input_item in input.split(',')]
        for hash in input_list:
            scan_report = vt.get_file_report(hash)
            return render_template("vt-hash.html", sd=scan_report.get("results").get("scan_date"),
                                   pos=scan_report.get("results").get("positives"),
                                   total=scan_report.get("results").get("total"),
                                   md5=scan_report.get("results").get("md5"),
                                   sha1=scan_report.get("results").get("sha1"),
                                   link=scan_report.get("results").get("permalink"))

    except Exception as e:
        return render_template("vt-hash.html", text="Error: Please try again.")

@app.route('/assets/<path:path>')
def static_file(path):
    return send_from_directory("assets",path)

@app.route("/threatcrwod/<email>")
def threatcrowd(email):
    req = requests.get("https://www.threatcrowd.org/searchApi/v2/email/report/", params={"email": email})
    j = json.loads(req.text)
    K = 3

    # compute distance between two domains
    def domain_similarity(s1, s2):

        if len(s1) > len(s2):
            s1, s2 = s2, s1
        distances = range(len(s1) + 1)

        for i2, c2 in enumerate(s2):
            distances_ = [i2 + 1]
            for i1, c1 in enumerate(s1):
                if c1 == c2:
                    distances_.append(distances[i1])
                else:
                    distances_.append(1 + min((distances[i1], distances[i1 + 1], distances_[-1])))
            distances = distances_
        return distances[-1]

    # compute distance matrix for all domains
    count = len(j['domains'])
    similarity = []
    for count_index1 in range(0, count):
        tmp = []
        for count_index2 in range(0, count):
            if count_index1 == count_index2:
                simi = 0
            elif count_index1 < count_index2:
                simi = domain_similarity(j['domains'][count_index1], j['domains'][count_index2])
            else:
                simi = similarity[count_index2][count_index1]
            tmp.append(simi)
        similarity.append(tmp)

    # scale the distance matrix
    adist = np.array(similarity)
    adist = adist * 10

    # compute coordinates matrix
    mds = manifold.MDS(n_components=2, dissimilarity="precomputed", random_state=6)
    results = mds.fit(adist)
    coords = results.embedding_

    # clustering all points according to given centroid
    def cluster_points(X, mu):
        clusters = {}
        for x in X:
            bestmukey = min([(i[0], np.linalg.norm(x - mu[i[0]])) \
                             for i in enumerate(mu)], key=lambda t: t[1])[0]
            try:
                clusters[bestmukey].append(x)
            except KeyError:
                clusters[bestmukey] = [x]
        return clusters

    # relocate centroids
    def reevaluate_centers(mu, clusters):
        newmu = []
        keys = sorted(clusters.keys())
        for key in keys:
            newmu.append(np.mean(clusters[key], axis=0))
        return newmu

    # check convergence of centroids
    def has_converged(mu, oldmu):
        return (set([tuple(a) for a in mu]) == set([tuple(a) for a in oldmu]))

    # find stable centroids
    def find_centroids(X, k):
        # Initialize to K random centers
        oldmu = random.sample(X, k)
        mu = random.sample(X, k)
        while not has_converged(mu, oldmu):
            oldmu = mu
            # Assign all points in X to clusters
            clusters = cluster_points(X, mu)
            # Reevaluate centers
            mu = reevaluate_centers(oldmu, clusters)
        return (mu, clusters)

    # Euclidean distance
    def Eu_distance(P1, P2):
        dist = np.sqrt(pow((P1[0] - P2[0]), 2) + pow((P1[1] - P2[1]), 2))
        return dist

    class domain_coordinates:
        'for storing domain instances'

        def __init__(self, x_coordinate, y_coordinate, cluster, domain_name, is_center):
            self.x_coordinate = x_coordinate
            self.y_coordinate = y_coordinate
            self.cluster = cluster
            self.domain_name = domain_name
            self.is_center = is_center

    # Find corresponding domain name for given coordinates
    def find_domain(coordinates):
        for m in range(0, count):
            if coordinates[0] == int(coords[m][0]) and coordinates[1] == int(coords[m][1]):
                return str(j['domains'][m])

    def find_result(X, k):
        (M, C) = find_centroids(X, k)
        result = {}
        # change to integer coordinates
        for l in range(0, k):
            for point_index in range(0, len(C[l])):
                C[l][point_index] = [int(C[l][point_index][0]), int(C[l][point_index][1])]
        # find acutal center
        for i in range(0, k):
            dis_array = []
            for point in C[i]:
                dis_array.append(Eu_distance(point, M[i]))
            index = dis_array.index(min(dis_array))
            # Store center
            center_point = C[i].pop(index)
            result[str(i)] = [[center_point[0], center_point[1], find_domain(center_point)]]

            for k in range(0, len(C[i])):
                if k < 3:
                    # Store first 3 non-center domains
                    result[str(i)].append([C[i][k][0], C[i][k][1], find_domain(C[i][k])])

        return result

    return render_template("visualization.htm", data=json.dumps(find_result(coords, K)))


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