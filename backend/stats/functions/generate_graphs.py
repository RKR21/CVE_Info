import base64
import matplotlib.pyplot as plt
from io import BytesIO

""" cvss_two_dict = {
        'AV' : {'L' : 0, 'A' : 0, 'N' : 0},
        'AC' : {'H' : 0, 'M' : 0, 'L' : 0},
        'Au' : {'M' : 0, 'S' : 0, 'N' : 0},
        'C' : {'N' : 0, 'P' : 0, 'C' : 0},
        'I' : {'N' : 0, 'P' : 0, 'C' : 0},
        'A' : {'N' : 0, 'P' : 0, 'C' : 0},
 """

# GRAPHS IN ACCORDIAN
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
        #print(percents)
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
    plt.xticks(rotation=45, ha='right')  # Adjust the rotation angle and alignment as needed

    fig.tight_layout()
    

    img = BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    b64_image = base64.b64encode(img.read()).decode('utf-8')
    img.close()
    plt.clf()
    return b64_image

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
    