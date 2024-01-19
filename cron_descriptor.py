from cron_descriptor import get_description
 
 
import os
 
# with open("cron_expressions.txt") as f:
    # for line in f:
        # description = get_description(line.strip())
        # print(description)
        


cron_expressions = [
"0 22 * * 1-6",
"*/5 17,18,19 * * *"
]


for expression in cron_expressions:
    description = get_description(expression)
    print(description)