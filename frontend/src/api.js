const API_BASE_URL='http://127.0.0.1:8000'

export async function apirequest(path,options={}) {
    const  { apiKey, ...fetchOptions } = options

    const headers={
        'Content-Type':'application/json',
        ...fetchOptions.headers,
    }

    if (apiKey) {
        headers['X-API-KEY'] = apiKey
    }

    const response=await fetch(`${API_BASE_URL}${path}`,{...fetchOptions,headers,})
    const text=await response.text()
    let data
    try {
        data=text ? JSON.parse(text) : null
    } catch {
        data=text
    }
    if (!response.ok){
        const detail=data?.detail
        let message
        if (typeof detail === 'string') {
            message = detail
        } else if (Array.isArray(detail)) {
            message=detail.map(item => typeof item === 'object' && item!==null ? item.msg || JSON.stringify(item):String(item)).join('; ')
        }else if (detail && typeof detail === 'object') {
            message =detail.message || JSON.stringify(detail)
        } else if (typeof data === 'string' && data.trim()) {
            message=data
        }else {
            message=`Request failed with status ${response.status}`
        }
        throw new Error(message)
    }
    return data
}