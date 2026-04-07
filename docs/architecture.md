# PhishScamSense Architecture

Here are the Mermaid diagrams representing the high-level architecture and directory structure of the PhishScamSense project.

## Mindmap Representation

```mermaid
mindmap
  root((PhishScamSense))
    backend
      app
        api
        core
        models
        schemas
        services
        workers
      tests
    ml
      notebooks
      src
        data
        features
        inference
        models
        training
    extension
      assets
      entrypoints
        popup
      lib
    data
      processed
      raw
    infrastructure
      airflow
    docs
      prd
    scripts
```

## Flowchart Representation

```mermaid
graph LR
    Root[PhishScamSense] --> Backend[backend/]
    Root --> ML[ml/]
    Root --> Ext[extension/]
    Root --> Infra[infrastructure/]
    Root --> Data[data/]

    %% Backend Structure
    Backend --> B_App[app/]
    Backend --> B_Tests[tests/]
    B_App --> B_Api[api/]
    B_App --> B_Core[core/]
    B_App --> B_Services[services/]
    B_App --> B_Workers[workers/]

    %% ML Structure
    ML --> M_Notebooks[notebooks/]
    ML --> M_Src[src/]
    M_Src --> M_Features[features/]
    M_Src --> M_Models[models/]
    M_Src --> M_Training[training/]

    %% Extension Structure
    Ext --> E_Entry[entrypoints/]
    Ext --> E_Lib[lib/]
    E_Entry --> E_Popup[popup/]
```
