############################################################
# CyberShield
# Cybersecurity Analytics & Threat Intelligence Platform
#
# Exploratory Data Analysis (EDA)
#
# Dataset : UNSW-NB15
############################################################

data <- read.csv("visualization/visualization_dataset.csv")
head(data)
dim(data)
list.files("visualization")
install.packages("ggplot2")
install.packages("dplyr")
library(ggplot2)
library(dplyr)
sessionInfo()

# ==========================================================
# EDA 1 - Attack Category Distribution
# ==========================================================
attack_count <- as.data.frame(table(data$attack_cat))

colnames(attack_count) <- c("attack_cat", "Count")

print(attack_count)

print(attack_count)

ggplot(attack_count,
       aes(x = reorder(attack_cat, Count),
           y = Count)) +
  geom_col(fill = "steelblue") +
  labs(
    title = "Distribution of Attack Categories",
    x = "Attack Category",
    y = "Number of Records"
  ) +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1))

# ==========================================================
# EDA 2 - Normal vs Attack Distribution
# ==========================================================

binary_count <- count(data, label)

binary_count$Traffic <- ifelse(binary_count$label == 0,
                               "Normal",
                               "Attack")

print(binary_count)

ggplot(binary_count,
       aes(x = Traffic,
           y = n,
           fill = Traffic)) +
  geom_col() +
  labs(
    title = "Normal vs Attack Distribution",
    x = "Traffic Type",
    y = "Number of Records"
  ) +
  theme_minimal()

# ==========================================================
# EDA 3 - Protocol Distribution
# ==========================================================

protocol_count <- count(data, proto)

print(protocol_count)

ggplot(protocol_count,
       aes(x = reorder(proto, -n), y = n)) +
  geom_col(fill = "darkgreen") +
  labs(
    title = "Protocol Distribution",
    x = "Protocol",
    y = "Number of Records"
  ) +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1))

############################################################
# EDA 4 - Service Distribution
############################################################

service_count <- as.data.frame(table(data$service))

colnames(service_count) <- c("Service", "Count")

print(service_count)

ggplot(service_count,
       aes(x = reorder(Service, Count),
           y = Count)) +
  geom_col(fill = "orange") +
  labs(
    title = "Distribution of Network Services",
    x = "Service",
    y = "Number of Records"
  ) +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 90, hjust = 1))

############################################################
# EDA 5 - Connection State Distribution
############################################################

state_count <- as.data.frame(table(data$state))

colnames(state_count) <- c("State", "Count")

print(state_count)

ggplot(state_count,
       aes(x = reorder(State, Count),
           y = Count)) +
  geom_col(fill = "purple") +
  labs(
    title = "Connection State Distribution",
    x = "Connection State",
    y = "Number of Records"
  ) +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1))


install.packages("corrplot")
library(corrplot)
############################################################
# EDA 6 - Correlation Heatmap
############################################################

numeric_data <- data[sapply(data, is.numeric)]

cor_matrix <- cor(numeric_data)

corrplot(cor_matrix,
         method = "color",
         tl.cex = 0.6,
         number.cex = 0.5)


############################################################
# EDA 7 - Scatter Plot
############################################################

ggplot(data,
       aes(x = sbytes,
           y = dbytes)) +
  geom_point(
    color = "blue",
    alpha = 0.4
  ) +
  labs(
    title = "Source Bytes vs Destination Bytes",
    x = "Source Bytes",
    y = "Destination Bytes"
  ) +
  theme_minimal()

############################################################
# EDA 8 - Density Plot
############################################################

ggplot(data, aes(x = rate)) +
  geom_density(fill = "red", alpha = 0.4) +
  labs(
    title = "Density Plot of Network Rate",
    x = "Rate",
    y = "Density"
  ) +
  theme_minimal()