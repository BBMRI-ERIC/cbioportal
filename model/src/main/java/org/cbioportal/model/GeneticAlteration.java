package org.cbioportal.model;

import java.io.Serializable;

public class GeneticAlteration implements Serializable {
    
    private Integer entrezGeneId;
    private String values;
    private String[] splitValues;
    private Gene gene;

    public Integer getEntrezGeneId() {
        return entrezGeneId;
    }

    public void setEntrezGeneId(Integer entrezGeneId) {
        this.entrezGeneId = entrezGeneId;
    }

    public String getValues() {
        return values;
    }

    public void setValues(String values) {
        this.values = values;
    }

    public String[] getSplitValues() {

        if (splitValues == null) {
            splitValues = values.split(",");
        }
        return splitValues;
    }

    public Gene getGene() {
        return gene;
    }

    public void setGene(Gene gene) {
        this.gene = gene;
    }
}
