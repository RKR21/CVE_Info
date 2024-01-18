import base64
import matplotlib.pyplot as plt
from io import BytesIO

# generates pie charts for each metric in the vector
def generate_cvss_graphs(dict, occurrences):
    images = []
    for key in dict:
        sizes = []
        percents = []
        labels = dict[key].keys()
        for j in dict[key]:
            sizes.append(dict[key][j])
            rounded = round((dict[key][j] / occurrences) * 100, 1)
            percents.append(rounded)
        plt.pie(percents, labels=None, autopct='', startangle=90, pctdistance=.2)
        legend_labels = [f'{category}: {value}%' for category, value in zip(labels, percents)]
        plt.legend(legend_labels, title='Percentages', loc='upper left', bbox_to_anchor=(0, 1))
        plt.title(key)
        img = BytesIO()
        plt.savefig(img, format='png')
        img.seek(0)
        b64_image = base64.b64encode(img.read()).decode('utf-8')
        img.close()
        images.append(b64_image)
    plt.clf()
    return images

# generates graph showing number of cves per year
def generate_num_cves_per_year_graph(dict):
    categories = list(dict.keys())
    values = list(dict.values())
    plt.bar(categories, values)

    fig, ax = plt.subplots()
    ax.bar(categories, values)

    ax.set_xlabel('Year')
    ax.set_ylabel('Frequency')
    ax.set_title("Number of CVEs Per Year")

    # Rotate x-axis labels
    plt.xticks(rotation=45, ha='right')

    fig.tight_layout()
    

    img = BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    b64_image = base64.b64encode(img.read()).decode('utf-8')
    img.close()
    plt.clf()
    return b64_image

# generates graph showing average yearly base score
def generate_avg_yearly_base_score_graph(dict):
    x = list(dict.keys())
    y = []

    for key in dict:
        y.append(dict[key][0])
    plt.plot(x, y)
    plt.xlabel('Year')
    plt.ylabel('AVG Base Score')
    plt.title('Average Yearly CVE Severity')
    

    img = BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    b64_image = base64.b64encode(img.read()).decode('utf-8')
    img.close()
    plt.clf()
    return b64_image
    